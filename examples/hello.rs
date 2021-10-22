use env_logger::{self, Env};
use fast_router::router::Router;
use log::info;

fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let mut r = Router::default();
    let mut admin = r.group("user");
    {
        admin.get(":name/:id:u32", |c| {
            let name = c.param("name").unwrap();
            info!("取到参数：{}", name);
        })
    }
    r.run("127.0.0.1:80");
}
