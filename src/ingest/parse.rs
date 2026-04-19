use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    pub device_type: &'static str,
    pub os: &'static str,
    pub browser: &'static str,
}

pub fn parse_user_agent(ua: &str) -> DeviceInfo {
    let lower = ua.to_ascii_lowercase();

    let browser = match &lower {
        s if s.contains("edg/") || s.contains("edge/") => "edge",
        s if s.contains("opr/") || s.contains("opera") => "opera",
        s if s.contains("firefox/") => "firefox",
        s if s.contains("chrome/") && !s.contains("chromium/") => "chrome",
        s if s.contains("chromium/") => "chromium",
        s if s.contains("safari/") && !s.contains("chrome/") => "safari",
        s if s.contains("curl/") => "curl",
        s if s.contains("wget/") => "wget",
        _ => "other",
    };

    let os = match &lower {
        // iOS must be checked before macOS because iPhone/iPad UAs contain "Mac OS X".
        s if s.contains("iphone") || s.contains("ipad") || s.contains("ipod") => "ios",
        s if s.contains("android") => "android",
        s if s.contains("windows nt") => "windows",
        s if s.contains("mac os x") || s.contains("macos") => "macos",
        s if s.contains("cros") => "chromeos",
        s if s.contains("linux") => "linux",
        _ => "other",
    };

    let is_bot = is_bot(&lower);

    let device_type = if is_bot {
        "bot"
    } else if lower.contains("ipad") || lower.contains("tablet") {
        "tablet"
    } else if lower.contains("mobi") || lower.contains("iphone") || lower.contains("android") {
        "mobile"
    } else {
        "desktop"
    };

    DeviceInfo {
        device_type,
        os,
        browser,
    }
}

fn is_bot(lower_ua: &str) -> bool {
    const BOT_TOKENS: &[&str] = &[
        "bot",
        "crawler",
        "spider",
        "slurp",
        "facebookexternalhit",
        "embedly",
        "vkshare",
        "quora link preview",
        "outbrain",
        "pinterestbot",
        "pinterest",
        "telegrambot",
        "whatsapp",
        "duckduckbot",
        "skypeuripreview",
        "yandex",
        "applebot",
        "headlesschrome",
        "lighthouse",
        "axios",
        "python-requests",
        "go-http-client",
    ];
    BOT_TOKENS.iter().any(|t| lower_ua.contains(t))
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct UtmParams {
    pub source: Option<String>,
    pub medium: Option<String>,
    pub campaign: Option<String>,
    pub term: Option<String>,
    pub content: Option<String>,
}

pub fn parse_utm(url: &str) -> UtmParams {
    let Ok(parsed) = Url::parse(url) else {
        return UtmParams::default();
    };

    let mut out = UtmParams::default();
    for (k, v) in parsed.query_pairs() {
        let value = v.trim();
        if value.is_empty() {
            continue;
        }
        let value = Some(value.to_string());
        match k.as_ref() {
            "utm_source" => out.source = value,
            "utm_medium" => out.medium = value,
            "utm_campaign" => out.campaign = value,
            "utm_term" => out.term = value,
            "utm_content" => out.content = value,
            _ => {}
        }
    }
    out
}

/// Classify the traffic source from UTM params + referer.
///
/// Priority: utm_source > known referer mapping > raw referer host > "direct".
pub fn classify_source(utm: &UtmParams, referer: Option<&str>) -> Option<String> {
    if let Some(src) = utm.source.as_ref().map(|s| s.to_ascii_lowercase()) {
        return Some(normalize_source(&src));
    }

    if let Some(ref_url) = referer
        && !ref_url.is_empty()
        && let Ok(parsed) = Url::parse(ref_url)
        && let Some(host) = parsed.host_str()
    {
        let host_l = host.to_ascii_lowercase();
        return Some(classify_host(&host_l));
    }

    Some("direct".to_string())
}

fn classify_host(host: &str) -> String {
    let host = host.trim_start_matches("www.");
    for (needle, label) in KNOWN_SOURCES {
        if host == *needle || host.starts_with(needle) {
            return (*label).to_string();
        }
    }
    host.to_string()
}

fn normalize_source(s: &str) -> String {
    for (needle, label) in KNOWN_SOURCES {
        let n = needle.trim_end_matches('.');
        // Exact match, or match at a token boundary: "google." / "google-"
        // should hit, "notgoogle" / "googlelike" should not.
        if s == n || s == *needle {
            return (*label).to_string();
        }
        if let Some(rest) = s.strip_prefix(n) {
            match rest.as_bytes().first() {
                Some(b'.') | Some(b'-') | Some(b'_') => return (*label).to_string(),
                _ => {}
            }
        }
    }
    s.to_string()
}

/// Host / utm_source substrings mapped to canonical source labels.
/// Grouped by category in the label (e.g. "google" is a search engine, "twitter" is social).
const KNOWN_SOURCES: &[(&str, &str)] = &[
    // search engines
    ("google.", "google"),
    ("bing.", "bing"),
    ("duckduckgo.", "duckduckgo"),
    ("yahoo.", "yahoo"),
    ("yandex.", "yandex"),
    ("ecosia.", "ecosia"),
    ("brave.", "brave-search"),
    ("kagi.", "kagi"),
    ("qwant.", "qwant"),
    ("baidu.", "baidu"),
    // social
    ("facebook.", "facebook"),
    ("fb.", "facebook"),
    ("instagram.", "instagram"),
    ("twitter.", "twitter"),
    ("x.com", "twitter"),
    ("t.co", "twitter"),
    ("linkedin.", "linkedin"),
    ("lnkd.in", "linkedin"),
    ("reddit.", "reddit"),
    ("pinterest.", "pinterest"),
    ("youtube.", "youtube"),
    ("youtu.be", "youtube"),
    ("tiktok.", "tiktok"),
    ("snapchat.", "snapchat"),
    ("mastodon.", "mastodon"),
    ("bsky.app", "bluesky"),
    ("threads.", "threads"),
    ("whatsapp.", "whatsapp"),
    ("t.me", "telegram"),
    ("telegram.", "telegram"),
    ("discord.", "discord"),
    ("ycombinator.", "hackernews"),
    ("hn.", "hackernews"),
    // email
    ("mail.google.", "email"),
    ("outlook.", "email"),
    ("mail.yahoo.", "email"),
    ("proton.me", "email"),
    ("protonmail.", "email"),
    ("fastmail.", "email"),
    ("icloud.", "email"),
];

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn chrome_on_macos_desktop() {
        let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36";
        let d = parse_user_agent(ua);
        assert_eq!(d.device_type, "desktop");
        assert_eq!(d.os, "macos");
        assert_eq!(d.browser, "chrome");
    }

    #[test]
    fn iphone_safari_mobile() {
        let ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1";
        let d = parse_user_agent(ua);
        assert_eq!(d.device_type, "mobile");
        assert_eq!(d.os, "ios");
        assert_eq!(d.browser, "safari");
    }

    #[test]
    fn firefox_on_windows() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0";
        let d = parse_user_agent(ua);
        assert_eq!(d.device_type, "desktop");
        assert_eq!(d.os, "windows");
        assert_eq!(d.browser, "firefox");
    }

    #[test]
    fn ipad_is_tablet() {
        let ua = "Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15";
        let d = parse_user_agent(ua);
        assert_eq!(d.device_type, "tablet");
        assert_eq!(d.os, "ios");
    }

    #[test]
    fn googlebot_is_bot() {
        let ua = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
        let d = parse_user_agent(ua);
        assert_eq!(d.device_type, "bot");
    }

    #[test]
    fn utm_parsed() {
        let utm = parse_utm(
            "https://example.com/?utm_source=twitter&utm_medium=social&utm_campaign=launch",
        );
        assert_eq!(utm.source.as_deref(), Some("twitter"));
        assert_eq!(utm.medium.as_deref(), Some("social"));
        assert_eq!(utm.campaign.as_deref(), Some("launch"));
    }

    #[test]
    fn utm_empty_values_ignored() {
        let utm = parse_utm("https://example.com/?utm_source=&utm_medium=social");
        assert_eq!(utm.source, None);
        assert_eq!(utm.medium.as_deref(), Some("social"));
    }

    #[test]
    fn classify_twitter_referer() {
        let utm = UtmParams::default();
        let s = classify_source(&utm, Some("https://twitter.com/somepost"));
        assert_eq!(s.as_deref(), Some("twitter"));
    }

    #[test]
    fn classify_x_com_as_twitter() {
        let utm = UtmParams::default();
        let s = classify_source(&utm, Some("https://x.com/status/1"));
        assert_eq!(s.as_deref(), Some("twitter"));
    }

    #[test]
    fn classify_google_search() {
        let utm = UtmParams::default();
        let s = classify_source(&utm, Some("https://www.google.com/search?q=foo"));
        assert_eq!(s.as_deref(), Some("google"));
    }

    #[test]
    fn classify_utm_wins_over_referer() {
        let utm = UtmParams {
            source: Some("newsletter".into()),
            ..Default::default()
        };
        let s = classify_source(&utm, Some("https://twitter.com/somepost"));
        assert_eq!(s.as_deref(), Some("newsletter"));
    }

    #[test]
    fn classify_direct_when_no_referer() {
        let utm = UtmParams::default();
        let s = classify_source(&utm, None);
        assert_eq!(s.as_deref(), Some("direct"));
    }

    #[test]
    fn classify_unknown_host_returns_host() {
        let utm = UtmParams::default();
        let s = classify_source(&utm, Some("https://www.somerandomsite.net/post"));
        assert_eq!(s.as_deref(), Some("somerandomsite.net"));
    }
}
