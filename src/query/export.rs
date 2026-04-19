use std::time::Duration;

use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::Response;
use futures::TryStreamExt;
use serde::Deserialize;
use sqlx::{QueryBuilder, Sqlite};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::auth::ReadAuth;
use crate::error::{AppError, AppResult};
use crate::query::{EVENTS_COLUMNS, EventFilters, push_filters};
use crate::state::AppState;

/// Hard row cap independent of the time deadline. Even a well-behaved consumer
/// gets cut off if the scan would dump an absurd amount of data. The time
/// deadline is in `config.server.export_deadline_secs`.
const EXPORT_ROW_CAP: usize = 5_000_000;

/// Export filters. Fields are duplicated from `EventFilters` rather than
/// flattened because `serde_urlencoded` (what axum's `Query` uses) can't
/// deserialize numeric types through `#[serde(flatten)]` — it stringifies
/// everything in the intermediate map, and then the inner `Option<i64>`
/// fields fail with "invalid type: string, expected i64". Flattening would
/// silently break `from=`, `to=` on the URL.
///
/// `limit` / `offset` are intentionally absent: `/export` streams to the
/// configured row cap + time deadline. Pagination belongs on `/events`.
#[derive(Debug, Deserialize, Default)]
pub struct ExportQuery {
    pub from: Option<i64>,
    pub to: Option<i64>,
    pub event_type: Option<String>,
    pub source: Option<String>,
    pub device_type: Option<String>,
    pub segment: Option<String>,
    pub url: Option<String>,
    pub user_id: Option<String>,
    pub country: Option<String>,
    #[serde(default = "default_format")]
    pub format: String,
}

impl ExportQuery {
    fn to_filters(&self) -> EventFilters {
        EventFilters {
            from: self.from,
            to: self.to,
            event_type: self.event_type.clone(),
            source: self.source.clone(),
            device_type: self.device_type.clone(),
            segment: self.segment.clone(),
            url: self.url.clone(),
            user_id: self.user_id.clone(),
            country: self.country.clone(),
            limit: None,
            offset: None,
        }
    }
}

fn default_format() -> String {
    "ndjson".into()
}

pub async fn export_handler(
    State(state): State<AppState>,
    _auth: ReadAuth,
    Query(q): Query<ExportQuery>,
) -> AppResult<Response> {
    let format = q.format.to_ascii_lowercase();
    if format != "csv" && format != "ndjson" {
        return Err(AppError::BadRequest(
            "format must be 'csv' or 'ndjson'".into(),
        ));
    }

    // Cap simultaneous exports — each one pins a SQLite connection for up to
    // `export_deadline_secs`. With the default pool of 8, a handful of slow
    // readers would starve ingest, stats, and webhook workers. `try_acquire`
    // means an over-limit caller gets 429 immediately rather than piling up.
    let permit = match state.export_semaphore.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            tracing::warn!("export rejected: concurrency cap reached");
            return Err(AppError::RateLimited);
        }
    };

    let mut qb: QueryBuilder<Sqlite> =
        QueryBuilder::new(format!("SELECT {EVENTS_COLUMNS} FROM events WHERE 1=1"));
    let filters = q.to_filters();
    push_filters(&mut qb, &filters);
    qb.push(" ORDER BY ts ASC, id ASC");

    let (tx, rx) = mpsc::channel::<Result<String, std::io::Error>>(32);
    let pool = state.pool.clone();
    let is_csv = format == "csv";
    let deadline_secs = state.config.server.export_deadline_secs;
    let expose_hash = state.config.privacy.expose_visitor_hash;

    let expose_user = state.config.privacy.expose_user_payload;
    tokio::spawn(async move {
        // Hold the semaphore permit for the lifetime of the streaming task so
        // the slot stays reserved even after the HTTP handler has returned.
        let _permit = permit;

        let deadline = tokio::time::sleep(Duration::from_secs(deadline_secs));
        tokio::pin!(deadline);

        let mut qb = qb;
        let stream = qb.build_query_as::<ExportRow>().fetch(&pool);
        tokio::pin!(stream);

        if is_csv {
            let _ = tx.send(Ok(csv_header(expose_hash, expose_user))).await;
        }

        let mut rows_sent = 0usize;
        loop {
            let next = tokio::select! {
                _ = &mut deadline => {
                    tracing::warn!("export stream hit {}s deadline", deadline_secs);
                    break;
                }
                next = stream.try_next() => next,
            };
            let row = match next {
                Ok(Some(row)) => row,
                Ok(None) => break,
                Err(err) => {
                    tracing::warn!(error = ?err, "export stream error");
                    break;
                }
            };
            let line = if is_csv {
                row.to_csv(expose_hash, expose_user)
            } else {
                row.to_json_line(expose_hash, expose_user)
            };
            // Bound the send so a slow/backpressured client can't hold the
            // DB cursor indefinitely. 10s between row-sends is generous for
            // HTTP streaming; anything slower is effectively abandoned.
            let send = tx.send(Ok(line));
            match tokio::time::timeout(Duration::from_secs(10), send).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => break, // receiver dropped — client went away
                Err(_) => {
                    tracing::warn!("export send timed out — slow reader");
                    break;
                }
            }
            rows_sent += 1;
            if rows_sent >= EXPORT_ROW_CAP {
                tracing::warn!(rows = rows_sent, "export hit hard row cap");
                break;
            }
        }
    });

    let stream = ReceiverStream::new(rx);
    let body = Body::from_stream(stream);

    let content_type = if is_csv {
        "text/csv; charset=utf-8"
    } else {
        "application/x-ndjson"
    };
    let filename = if is_csv {
        "events.csv"
    } else {
        "events.ndjson"
    };

    let mut resp = Response::builder()
        .status(StatusCode::OK)
        .body(body)
        .unwrap();
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    h.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")).unwrap(),
    );
    Ok(resp)
}

#[derive(sqlx::FromRow)]
struct ExportRow {
    id: i64,
    ts: i64,
    event_type: String,
    event_name: Option<String>,
    url: String,
    page_title: Option<String>,
    user_agent: String,
    device_type: Option<String>,
    device_os: Option<String>,
    device_browser: Option<String>,
    referer: Option<String>,
    source: Option<String>,
    utm_source: Option<String>,
    utm_medium: Option<String>,
    utm_campaign: Option<String>,
    utm_term: Option<String>,
    utm_content: Option<String>,
    visitor_hash: String,
    segments: Option<String>,
    extra: Option<String>,
    user_id: Option<String>,
    country: Option<String>,
    user: Option<String>,
    session_id: Option<String>,
}

impl ExportRow {
    fn to_json_line(&self, expose_hash: bool, expose_user: bool) -> String {
        let parsed_segments = self
            .segments
            .as_deref()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok());
        let parsed_extra = self
            .extra
            .as_deref()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok());

        let mut obj = serde_json::json!({
            "id": self.id,
            "ts": self.ts,
            "event_type": self.event_type,
            "event_name": self.event_name,
            "url": self.url,
            "page_title": self.page_title,
            "user_agent": self.user_agent,
            "device_type": self.device_type,
            "device_os": self.device_os,
            "device_browser": self.device_browser,
            "referer": self.referer,
            "source": self.source,
            "utm_source": self.utm_source,
            "utm_medium": self.utm_medium,
            "utm_campaign": self.utm_campaign,
            "utm_term": self.utm_term,
            "utm_content": self.utm_content,
            "segments": parsed_segments,
            "extra": parsed_extra,
            "user_id": self.user_id,
            "country": self.country,
            "session_id": self.session_id,
        });
        if let Some(o) = obj.as_object_mut() {
            // Match `/events`: when the operator hasn't opted into exposing
            // the hash, the field is omitted entirely rather than emitted as
            // null. An explicit null would still tell callers the column
            // exists in the DB.
            if expose_hash {
                o.insert(
                    "visitor_hash".into(),
                    serde_json::Value::String(self.visitor_hash.clone()),
                );
            }
            // The raw signed `user` blob carries PII (email/plan/etc.). Keep
            // it out of the response unless the operator explicitly opted in
            // — `user_id` stays available for attribution regardless.
            if expose_user {
                let user_value = self
                    .user
                    .as_deref()
                    .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok());
                o.insert("user".into(), user_value.unwrap_or(serde_json::Value::Null));
            }
        }
        let mut line = serde_json::to_string(&obj).unwrap_or_else(|_| "{}".into());
        line.push('\n');
        line
    }

    fn to_csv(&self, expose_hash: bool, expose_user: bool) -> String {
        let mut out = String::with_capacity(512);
        csv_push(&mut out, &self.id.to_string());
        csv_push(&mut out, &self.ts.to_string());
        csv_push(&mut out, &self.event_type);
        csv_push(&mut out, self.event_name.as_deref().unwrap_or(""));
        csv_push(&mut out, &self.url);
        csv_push(&mut out, self.page_title.as_deref().unwrap_or(""));
        csv_push(&mut out, &self.user_agent);
        csv_push(&mut out, self.device_type.as_deref().unwrap_or(""));
        csv_push(&mut out, self.device_os.as_deref().unwrap_or(""));
        csv_push(&mut out, self.device_browser.as_deref().unwrap_or(""));
        csv_push(&mut out, self.referer.as_deref().unwrap_or(""));
        csv_push(&mut out, self.source.as_deref().unwrap_or(""));
        csv_push(&mut out, self.utm_source.as_deref().unwrap_or(""));
        csv_push(&mut out, self.utm_medium.as_deref().unwrap_or(""));
        csv_push(&mut out, self.utm_campaign.as_deref().unwrap_or(""));
        csv_push(&mut out, self.utm_term.as_deref().unwrap_or(""));
        csv_push(&mut out, self.utm_content.as_deref().unwrap_or(""));
        if expose_hash {
            csv_push(&mut out, &self.visitor_hash);
        }
        csv_push(&mut out, self.segments.as_deref().unwrap_or(""));
        csv_push(&mut out, self.extra.as_deref().unwrap_or(""));
        csv_push(&mut out, self.user_id.as_deref().unwrap_or(""));
        csv_push(&mut out, self.country.as_deref().unwrap_or(""));
        if expose_user {
            csv_push(&mut out, self.user.as_deref().unwrap_or(""));
        }
        csv_push_last(&mut out, self.session_id.as_deref().unwrap_or(""));
        out.push('\n');
        out
    }
}

fn csv_header(expose_hash: bool, expose_user: bool) -> String {
    // Column list mirrors `to_csv`: optional columns are omitted from BOTH
    // header and every row when their privacy flag is off, so an export
    // consumer can't learn the column exists in the schema.
    let mut cols = String::from(
        "id,ts,event_type,event_name,url,page_title,user_agent,device_type,\
         device_os,device_browser,referer,source,utm_source,utm_medium,\
         utm_campaign,utm_term,utm_content",
    );
    if expose_hash {
        cols.push_str(",visitor_hash");
    }
    cols.push_str(",segments,extra,user_id,country");
    if expose_user {
        cols.push_str(",user");
    }
    cols.push_str(",session_id\n");
    cols
}

fn csv_push(out: &mut String, field: &str) {
    csv_field(out, field);
    out.push(',');
}

fn csv_push_last(out: &mut String, field: &str) {
    csv_field(out, field);
}

fn csv_field(out: &mut String, field: &str) {
    // Pre-scrub: strip control chars that are never legitimate in an analytics
    // field AND would let an attacker smuggle payloads past the formula-trigger
    // check (`\0=HYPERLINK(...)` — \0 is not a trigger byte, consumers drop
    // leading NULs, exposing the `=`). We also drop BOM / zero-width chars
    // that editors silently normalize away, revealing an unquoted formula.
    //
    // The filter list is small and the overwhelmingly common case is "no
    // match" — skip the allocation and borrow the input when nothing needs
    // stripping.
    use std::borrow::Cow;
    let needs_scrub = field
        .chars()
        .any(|c| matches!(c, '\0' | '\u{feff}' | '\u{200b}' | '\u{200c}' | '\u{200d}'));
    let scrubbed: Cow<'_, str> = if needs_scrub {
        Cow::Owned(
            field
                .chars()
                .filter(|c| !matches!(*c, '\0' | '\u{feff}' | '\u{200b}' | '\u{200c}' | '\u{200d}'))
                .collect(),
        )
    } else {
        Cow::Borrowed(field)
    };

    // Formula-injection defense. Excel / LibreOffice / Sheets treat a cell
    // starting with any of these chars as a formula trigger (DDE, pipe
    // operator, percent-function in some locales) and may execute on open.
    // Prefix suspect fields with a single quote so they're literal text.
    //
    // Tab (\t) and vertical-tab (\x0b) / form-feed (\x0c) at the start are
    // whitespace-stripped by LibreOffice before formula parsing, so a leading
    // `\x0b=1+1` becomes `=1+1`. Treat the whole C0-control range (except
    // bytes we explicitly handle below) as formula triggers.
    //
    // Check on the first SCALAR, not the first byte: Sheets and LibreOffice
    // both normalize Unicode fullwidth / halfwidth / small-form variants of
    // `= + - @` back to their ASCII equivalents at parse time, so `＝HYPERLINK(...)`
    // (U+FF1D) becomes a live formula even though its first byte is 0xEF.
    // Handle the common fullwidth / small-form / Arabic variants explicitly.
    let is_formula_trigger = scrubbed.chars().next().is_some_and(|c| {
        matches!(
            c,
            '=' | '+' | '-' | '@' | '|' | '%' | '\t' | '\u{000b}' | '\u{000c}' | '\r'
                // Fullwidth variants (U+FF01..U+FF5E) that normalize to ASCII.
                | '\u{FF1D}' // ＝ fullwidth equals
                | '\u{FF0B}' // ＋ fullwidth plus
                | '\u{FF0D}' // － fullwidth hyphen-minus
                | '\u{FF20}' // ＠ fullwidth at
                | '\u{FF5C}' // ｜ fullwidth vertical line
                | '\u{FF05}' // ％ fullwidth percent
                // Small form variants (U+FE50..U+FE6F).
                | '\u{FE62}' // ﹢ small plus sign
                | '\u{FE63}' // ﹣ small hyphen-minus
                // Super/subscript equals — niche but normalizers pass them through.
                | '\u{207C}' // ⁼ superscript equals
                | '\u{208C}' // ₌ subscript equals
        )
    });
    // Force quoting on ANY record-boundary-looking char. A bare \r without \n
    // is the classic Mac line terminator that Excel / Python csv.reader /
    // Google Sheets accept as a record break → attacker-controlled titles /
    // URLs / UAs could forge rows. Unicode line separators (LS U+2028, PS
    // U+2029, NEL U+0085) are also treated as breaks by some parsers. VT/FF
    // are additional record-boundary triggers in some historical parsers.
    let has_breaker = scrubbed.contains('\r')
        || scrubbed.contains('\n')
        || scrubbed.contains('\u{000b}')
        || scrubbed.contains('\u{000c}')
        || scrubbed.contains('\u{2028}')
        || scrubbed.contains('\u{2029}')
        || scrubbed.contains('\u{0085}');
    let needs_quote =
        is_formula_trigger || scrubbed.contains(',') || scrubbed.contains('"') || has_breaker;
    if needs_quote {
        out.push('"');
        if is_formula_trigger {
            out.push('\'');
        }
        for c in scrubbed.chars() {
            if c == '"' {
                out.push('"');
            }
            out.push(c);
        }
        out.push('"');
    } else {
        out.push_str(&scrubbed);
    }
}

#[cfg(test)]
mod tests {
    use super::csv_field;

    fn emit(s: &str) -> String {
        let mut out = String::new();
        csv_field(&mut out, s);
        out
    }

    #[test]
    fn bare_cr_is_quoted() {
        // Classic-Mac \r: without forcing a quote, CSV consumers split rows
        // here. The attacker-controlled title `foo\rforged,row` would end
        // the cell and start a new record. Quoting keeps it one cell.
        let got = emit("foo\rforged,row");
        assert!(got.starts_with('"') && got.ends_with('"'));
        assert!(got.contains('\r'));
    }

    #[test]
    fn null_byte_is_dropped() {
        // After pre-scrub the null is gone, and the remaining `foobar` has
        // no special chars so it's emitted unquoted.
        assert_eq!(emit("foo\0bar"), "foobar");
    }

    #[test]
    fn unicode_line_separators_are_quoted() {
        for sep in ['\u{2028}', '\u{2029}', '\u{0085}'] {
            let got = emit(&format!("a{sep}b"));
            assert!(
                got.starts_with('"') && got.ends_with('"'),
                "{sep:?} should force quoting"
            );
        }
    }

    #[test]
    fn formula_prefix_still_triggers() {
        assert_eq!(emit("=1+1"), "\"'=1+1\"");
        assert_eq!(emit("@cmd"), "\"'@cmd\"");
    }

    #[test]
    fn plain_text_is_unquoted() {
        assert_eq!(emit("hello world"), "hello world");
    }

    #[test]
    fn null_prefix_cannot_smuggle_formula() {
        // Regression: attacker smuggled `\0=HYPERLINK(...)` past the formula
        // trigger check, then the null was stripped inside the quoted cell,
        // leaving a live `=...` formula. Pre-scrubbing kills the null BEFORE
        // the trigger check runs.
        let got = emit("\0=HYPERLINK(\"http://evil/\")");
        assert!(got.contains("'="), "formula marker must be prefixed: {got}");
        assert!(!got.contains('\0'));
    }

    #[test]
    fn vt_ff_prefix_is_quoted_and_prefixed() {
        // Regression: LibreOffice strips leading \x0b / \x0c as whitespace
        // before formula parsing, so these must be treated as triggers.
        // Output shape: `"'\x0b=1+1"` — quoted cell, apostrophe neutralizer,
        // then the original control byte + formula.
        let got_vt = emit("\u{000b}=1+1");
        assert!(
            got_vt.starts_with("\"'"),
            "missing quote+apostrophe: {got_vt:?}"
        );
        assert!(got_vt.contains("=1+1"));
        let got_ff = emit("\u{000c}=1+1");
        assert!(
            got_ff.starts_with("\"'"),
            "missing quote+apostrophe: {got_ff:?}"
        );
    }

    #[test]
    fn fullwidth_equals_is_treated_as_formula_trigger() {
        // Regression: bytewise check missed U+FF1D because its UTF-8 is
        // 0xEF 0xBC 0x9D. Sheets / LibreOffice normalize ＝ to = at parse
        // time, so a value starting with ＝HYPERLINK(...) would become a
        // live formula even though its first byte isn't a trigger.
        let got = emit("\u{FF1D}HYPERLINK(\"http://evil/\")");
        assert!(got.starts_with("\"'"), "fullwidth = must trigger: {got:?}");
        assert!(got.contains('\u{FF1D}'));
        let got_plus = emit("\u{FF0B}1+1");
        assert!(got_plus.starts_with("\"'"), "fullwidth + must trigger");
        let got_at = emit("\u{FF20}cmd");
        assert!(got_at.starts_with("\"'"), "fullwidth @ must trigger");
    }

    #[test]
    fn bom_and_zero_width_are_stripped() {
        // Excel strips BOM at file/cell start; zero-width chars are
        // invisible. Either lets an attacker hide a live formula.
        let got = emit("\u{feff}=1+1");
        assert!(got.contains("'="));
        let got_zwsp = emit("\u{200b}=1+1");
        assert!(got_zwsp.contains("'="));
    }
}
