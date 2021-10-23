use env_logger::{self, Env};
use fast_router::router::{Ctx, Router};
use log::info;

fn test(c:&mut Ctx){
    c.string("欢迎光临");
}

fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("debug")).init();

    let mut r = Router::default();

    let v = "闭包接收外部参数".to_string();
    r.before("any".into(), "",  move | c|{
        c.set_header("key", &v);
    });

    r.get("", test);

    let mut admin = r.group(":user");
    {
        admin.before("get".into(), "/:name/", |c| {
            let user: String = c.param("user").unwrap();
            c.set_header("test", user.as_str());
        });

        admin.get("/:name/:age:u8", |c| {
            let name: String = c.param("name").unwrap();
            let age: i32 = c.param("age").unwrap();
            let user: String = c.param("user").unwrap();
            c.string(format!("{} 你好：{}，你已经 {} 岁了", user, name, age).as_str());
        })
    }

    r.run("127.0.0.1:80");
}
