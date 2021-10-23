use env_logger::{self, Env};
use fast_web::router::json;

#[macro_use]
extern crate serde_derive;

use fast_web::router::{Ctx, Router};

#[derive(Serialize, Deserialize)]
struct Person {
    name: String,
    age: i32,
}

fn index(c: &mut Ctx) {
    c.string("欢迎光临，<a href='articles'>点击打开文章列表</a>");
}

fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("debug")).init();

    let mut r = Router::default();

    let v = "1234567".to_string();
    // 所有页面都会被设置token头
    r.before("any".into(), "", move |c| {
        c.set_header("token", &v);
        c.set_data("user_id", 1); // 过滤器中设置值
    });

    // 首页
    r.get("", index);

    r.get("/me", |c| {
        let age: i32 = c.data("user_id").unwrap(); // 后面的处理器中可以获取

        let lang = c.header("Accept-Language").unwrap_or_default();

        c.json(Person { name: lang, age });
    });

    // 文章分组
    let mut article = r.group("articles");
    {
        article.get("", |c| {
            c.string("文章列表<ul><li><a href='/articles/1'>第 1 篇文章</a></li><li><a href='/articles/2/'>第 2 篇文章</a></li></ul>");
        });

        article.get("/:id:i32", |c| {
            let id: i32 = c.param("id").unwrap();
            let q: String = c.query("id").unwrap_or_default();
            c.string(format!("这是第 {} 篇文章,参数：{}", id, q).as_str());
        });

        article.get("/json", |c| {
            c.json(json!({
                "code": 200,
                "success": true,
                "payload": {
                    "features": [
                        "serde",
                        "json"
                    ]
                }
            }));
        });
    }

    let mut user = r.group(":user");

    r.run("127.0.0.1:80");
}
