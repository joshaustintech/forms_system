use color_eyre::eyre::Result;
use once_cell::sync::Lazy;
use poem::{error::InternalServerError, get, handler, listener::TcpListener, web::{Html, Path}, Route, Server};
use tera::{Tera, Context};

static TEMPLATES: Lazy<Tera> = Lazy::new(|| {
    let mut tera = match Tera::new("templates/**/*") {
        Ok(t) => t,
        Err(e) => {
            println!("Parsing error(s): {e}");
            ::std::process::exit(1);
        }
    };
    tera.autoescape_on(vec![".html", ".sql"]);
    tera
});

#[handler]
fn hello() -> Result<Html<String>, poem::Error> {
    let mut context = Context::new();
    TEMPLATES
        .render("index.html", &context)
        .map_err(InternalServerError)
        .map(Html)
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    let app = Route::new().at("/", get(hello));
    Ok(
        Server::new(TcpListener::bind("0.0.0.0:3000"))
            .run(app)
            .await?
    )
}