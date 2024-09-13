#[macro_use] extern crate rocket;
use rocket::fs::{FileServer, relative};
use rocket_dyn_templates::{Template, context};
use rocket::form::Form;
use rocket::response::Redirect;
use rocket::http::{Cookie, CookieJar, Status, private::PrivateCookies};
use rocket::request::{FromRequest, Outcome};
use rocket::outcome::IntoOutcome;
use rocket::State;
use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};
use serde::{Serialize, Deserialize};
use bcrypt::{hash, verify, DEFAULT_COST};
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
struct WebForm {
    id: i64,
    title: String,
    fields: String,
    published: bool,
    author_id: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct User {
    id: i64,
    username: String,
    password_hash: String,
}

struct AuthenticatedUser(i64);

struct SessionStore(RwLock<HashMap<String, i64>>);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthenticatedUser {
    type Error = ();

    async fn from_request(request: &'r rocket::Request<'_>) -> Outcome<Self, Self::Error> {
        let session_store = request.rocket().state::<SessionStore>().unwrap();
        let session_id = request.cookies()
            .get_private("session_id")
            .and_then(|cookie| cookie.value().parse().ok());
        
        if let Some(session_id) = session_id {
            let sessions = session_store.0.read().unwrap();
            sessions.get(&session_id)
                .map(|&user_id| AuthenticatedUser(user_id))
                .or_forward(())
        } else {
            Outcome::Forward(())
        }
    }
}

#[get("/")]
async fn index(db: &State<SqlitePool>, user: Option<AuthenticatedUser>) -> Template {
    let forms = if let Some(AuthenticatedUser(user_id)) = user {
        sqlx::query_as!(WebForm, "SELECT * FROM forms WHERE author_id = ?", user_id)
            .fetch_all(db.inner())
            .await
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    Template::render("index", context! { forms: forms, logged_in: user.is_some() })
}

#[get("/login")]
fn login_page() -> Template {
    Template::render("login", context! {})
}

#[post("/login", data = "<login_form>")]
async fn login(
    db: &State<SqlitePool>,
    session_store: &State<SessionStore>,
    cookies: &CookieJar<'_>,
    login_form: Form<User>
) -> Result<Redirect, Status> {
    let user = sqlx::query_as!(User, 
        "SELECT * FROM users WHERE username = ?", 
        login_form.username
    )
    .fetch_optional(db.inner())
    .await
    .map_err(|_| Status::InternalServerError)?;

    if let Some(user) = user {
        if verify(&login_form.password_hash, &user.password_hash).map_err(|_| Status::InternalServerError)? {
            let session_id = Uuid::new_v4().to_string();
            session_store.0.write().unwrap().insert(session_id.clone(), user.id);
            cookies.add_private(Cookie::new("session_id", session_id));
            return Ok(Redirect::to(uri!(index)));
        }
    }

    Ok(Redirect::to(uri!(login_page)))
}

#[post("/logout")]
fn logout(session_store: &State<SessionStore>, cookies: &CookieJar<'_>) -> Redirect {
    if let Some(session_id) = cookies.get_private("session_id") {
        session_store.0.write().unwrap().remove(session_id.value());
    }
    cookies.remove_private(Cookie::named("session_id"));
    Redirect::to(uri!(index))
}

#[get("/register")]
fn register_page() -> Template {
    Template::render("register", context! {})
}

#[post("/register", data = "<register_form>")]
async fn register(db: &State<SqlitePool>, register_form: Form<User>) -> Result<Redirect, Status> {
    let password_hash = hash(&register_form.password_hash, DEFAULT_COST).map_err(|_| Status::InternalServerError)?;
    
    sqlx::query!(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        register_form.username,
        password_hash
    )
    .execute(db.inner())
    .await
    .map_err(|_| Status::InternalServerError)?;

    Ok(Redirect::to(uri!(login_page)))
}

#[get("/form/new")]
fn new_form(user: AuthenticatedUser) -> Template {
    Template::render("form_edit", context! { form: None::<WebForm> })
}

#[post("/form", data = "<form_data>")]
async fn create_form(db: &State<SqlitePool>, user: AuthenticatedUser, form_data: Form<WebForm>) -> Result<Redirect, Status> {
    let form = form_data.into_inner();
    sqlx::query!(
        "INSERT INTO forms (title, fields, published, author_id) VALUES (?, ?, ?, ?)",
        form.title,
        form.fields,
        form.published,
        user.0
    )
    .execute(db.inner())
    .await
    .map_err(|_| Status::InternalServerError)?;

    Ok(Redirect::to(uri!(index)))
}

#[get("/form/<id>")]
async fn edit_form(db: &State<SqlitePool>, user: AuthenticatedUser, id: i64) -> Result<Template, Status> {
    let form = sqlx::query_as!(WebForm, "SELECT * FROM forms WHERE id = ? AND author_id = ?", id, user.0)
        .fetch_optional(db.inner())
        .await
        .map_err(|_| Status::InternalServerError)?;

    Ok(form.map(|form| Template::render("form_edit", context! { form: form }))
        .unwrap_or_else(|| Template::render("404", context! {})))
}

#[post("/form/<id>", data = "<form_data>")]
async fn update_form(db: &State<SqlitePool>, user: AuthenticatedUser, id: i64, form_data: Form<WebForm>) -> Result<Redirect, Status> {
    let form = form_data.into_inner();
    sqlx::query!(
        "UPDATE forms SET title = ?, fields = ?, published = ? WHERE id = ? AND author_id = ?",
        form.title,
        form.fields,
        form.published,
        id,
        user.0
    )
    .execute(db.inner())
    .await
    .map_err(|_| Status::InternalServerError)?;

    Ok(Redirect::to(uri!(index)))
}

#[post("/form/<id>/publish")]
async fn publish_form(db: &State<SqlitePool>, user: AuthenticatedUser, id: i64) -> Result<Redirect, Status> {
    sqlx::query!("UPDATE forms SET published = true WHERE id = ? AND author_id = ?", id, user.0)
        .execute(db.inner())
        .await
        .map_err(|_| Status::InternalServerError)?;

    Ok(Redirect::to(uri!(index)))
}

#[post("/form/<id>/unpublish")]
async fn unpublish_form(db: &State<SqlitePool>, user: AuthenticatedUser, id: i64) -> Result<Redirect, Status> {
    sqlx::query!("UPDATE forms SET published = false WHERE id = ? AND author_id = ?", id, user.0)
        .execute(db.inner())
        .await
        .map_err(|_| Status::InternalServerError)?;

    Ok(Redirect::to(uri!(index)))
}

#[post("/form/<id>/clone")]
async fn clone_form(db: &State<SqlitePool>, user: AuthenticatedUser, id: i64) -> Result<Redirect, Status> {
    sqlx::query!(
        "INSERT INTO forms (title, fields, published, author_id) 
         SELECT title || ' (Clone)', fields, false, ? FROM forms WHERE id = ? AND author_id = ?",
        user.0,
        id,
        user.0
    )
    .execute(db.inner())
    .await
    .map_err(|_| Status::InternalServerError)?;

    Ok(Redirect::to(uri!(index)))
}

#[post("/form/<id>/delete")]
async fn delete_form(db: &State<SqlitePool>, user: AuthenticatedUser, id: i64) -> Result<Redirect, Status> {
    sqlx::query!("DELETE FROM forms WHERE id = ? AND author_id = ?", id, user.0)
        .execute(db.inner())
        .await
        .map_err(|_| Status::InternalServerError)?;

    Ok(Redirect::to(uri!(index)))
}

#[launch]
fn rocket() -> _ {
    let db = SqlitePoolOptions::new()
        .connect_lazy("sqlite:forms.db")
        .expect("Failed to connect to SQLite");

    rocket::build()
        .mount("/", FileServer::from(relative!("static")))
        .mount("/", routes![
            index, login_page, login, logout, register_page, register,
            new_form, create_form, edit_form, update_form,
            publish_form, unpublish_form, clone_form, delete_form
        ])
        .manage(db)
        .manage(SessionStore(RwLock::new(HashMap::new())))
        .attach(Template::fairing())
}
