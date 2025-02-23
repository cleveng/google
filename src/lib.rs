use oauth2::basic::BasicClient;
use oauth2::reqwest::async_http_client;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope,
    TokenResponse, TokenUrl,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::error::Error;

pub struct Google {
    client: BasicClient,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct UserInfo {
    #[serde(rename = "sub")]
    pub open_id: String,

    #[serde(rename = "name")]
    pub username: String,
    given_name: Option<String>,
    family_name: Option<String>,

    #[serde(rename = "picture")]
    pub profile_url: String,

    pub email: String,
    pub email_verified: bool,
    locale: Option<String>,
}

impl Google {
    /// Creates a new instance of the Google authorization client.
    ///
    /// # Arguments
    ///
    /// * `appid` - The client ID provided by Google when registering the application.
    /// * `app_secret` - The client secret provided by Google when registering the
    ///   application.
    /// * `callback_url` - The URL that the user will be redirected to after authorization
    ///   is complete. This URL should be an endpoint in the application that will handle
    ///   the authorization code.
    ///
    /// # Returns
    ///
    /// * `Google` - A new instance of the Google authorization client.
    pub fn new(appid: String, app_secret: String, callback_url: String) -> Google {
        let client_id = ClientId::new(appid.clone());
        let client_secret = ClientSecret::new(app_secret.clone());

        let auth_url =
            AuthUrl::new("https://accounts.google.com/o/oauth2/auth".to_string()).unwrap();
        let token_url =
            TokenUrl::new("https://accounts.google.com/o/oauth2/token".to_string()).unwrap();

        let redirect_url = RedirectUrl::new(callback_url.clone()).unwrap();

        let client = BasicClient::new(client_id, Some(client_secret), auth_url, Some(token_url))
            .set_redirect_uri(redirect_url);

        Google { client }
    }

    /// Generates a URL that the user should be redirected to in order to authorize this
    /// application. This URL is the standard authorization URL for the OAuth2 flow with the
    /// Google OAuth2 provider, and includes the scopes required to fetch the user's profile
    /// information.
    pub fn get_redirect_url(&self) -> String {
        let (auth_url, _csrf_token) = self
            .client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("openid".to_string()))
            .add_scope(Scope::new("email".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .url();

        auth_url.to_string()
    }

    /// Fetches and returns the user's profile information from Google using the provided
    /// authorization code.
    ///
    /// This function exchanges the provided authorization code for an access token and then
    /// uses that token to request the user's profile information from Google's userinfo
    /// endpoint. The user's information is returned as a `UserInfo` struct.
    ///
    /// # Arguments
    ///
    /// * `code` - A `String` representing the authorization code received from Google's
    ///            OAuth2 authorization flow.
    ///
    /// # Returns
    ///
    /// * `Result<UserInfo, Box<dyn Error>>` - On success, returns `Ok(UserInfo)` containing
    ///   the user's profile information. On failure, returns `Err` with an error describing
    ///   what went wrong.
    ///
    /// # Errors
    ///
    /// This function can return an error if the authorization code exchange fails, if the
    /// request to fetch the user's profile information fails, or if parsing the response
    /// into a `UserInfo` struct fails.
    pub async fn get_userinfo(&self, code: String) -> Result<UserInfo, Box<dyn Error>> {
        let token = match self
            .client
            .exchange_code(AuthorizationCode::new(code))
            .request_async(async_http_client)
            .await
        {
            Ok(result) => result.access_token().clone(),
            Err(err) => {
                return Err(err.into());
            }
        };

        let response = Client::new()
            .get("https://www.googleapis.com/oauth2/v3/userinfo".to_string())
            .bearer_auth(&token.secret())
            .send()
            .await?;

        if !response.status().is_success() {
            return Err("Failed to fetch profile information".into());
        }

        let result = match response.json::<UserInfo>().await {
            Ok(result) => result,
            Err(err) => {
                return Err(err.into());
            }
        };

        Ok(result)
    }
}
