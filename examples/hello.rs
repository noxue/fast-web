use env_logger::{self, Env};
use fast_router::router::Router;
use log::info;

fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("trace")).init();

    let mut r = Router::default();
    let mut admin = r.group("user");
    {
        admin.get(":name:(.+)", |c| {
            let name: String = c.param("name").unwrap();
            // let id: i32 = c.param("id").unwrap();

            info!("取到参数：name:{:?}", name);
        })
    }
    r.run("127.0.0.1:80");
}
