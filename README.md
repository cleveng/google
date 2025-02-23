# Google Website Auth SDK for Rust

```rust
use dotenvy::dotenv;
use std::env;

use async_google_auth::Google;

fn main() {
    dotenv().ok();
    let appid = env::var("GOOGLE_CLIENT_ID").expect("GOOGLE_CLIENT_ID must be set");
    let app_secret =
        env::var("GOOGLE_CLIENT_SECRET").expect("GOOGLE_CLIENT_SECRET must be set");
    let callback_url =
        env::var("GOOGLE_CALLBACK_URL").expect("GOOGLE_CALLBACK_URL must be set");
    let google = Google::new(appid, app_secret, callback_url);

    let redirect_url = google.get_redirect_url();
    println!("Redirect URL: {}", redirect_url);

    let profile = google.get_userinfo("YOUR_AUTHORIZATION_CODE".to_string()).await.unwrap();
    println!("Profile: {:#?}", profile);
}
```
