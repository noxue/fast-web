use env_logger::{self, Env};
use fast_router::router::Router;
use log::info;

fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("debug")).init();

    let mut r = Router::default();

    r.get("", |mut c|{
        c.string("欢迎光临");
    });

    let mut admin = r.group(":user");
    {
        admin.before("get".into(), "/:name/", |mut c| {
            let user: String = c.param("user").unwrap();
            c.set_header("test", user.as_str());
        });

        admin.get("/:name/:age:u8", |mut c| {
            let name: String = c.param("name").unwrap();
            let age: i32 = c.param("age").unwrap();
            let user: String = c.param("user").unwrap();
            c.string(format!("{} 你好：{}，你已经 {} 岁了", user, name, age).as_str());
        })
    }

    r.run("127.0.0.1:80");
}
