# goweb-ssrf
golang tool for ssrf protection

what is ssrf ?  


# SSRF

> SSRF英文全拼为Server Side Request Forgery，翻译为服务端请求伪造。攻击者在未能取得服务器权限时，利用服务器漏洞以服务器的身份发送一条构造好的请求给服务器所在内网。关于内网资源的访问控制，想必大家心里都有数。

SSRF（Server-Side Request Forgery）是一种网络攻击技术，其目的是让服务器执行攻击者指定的请求。在这种攻击中，攻击者会利用网站的漏洞，欺骗服务器执行指定的请求，从而访问内部网络上的敏感信息或系统功能。

举个例子，如果一个网站允许用户提交 URL，并显示提交的 URL 对应的图片。如果这个网站没有对用户输入进行验证，攻击者就可以提交一个内部网络上的 URL，从而让服务器访问内部网络上的敏感信息。

防范 SSRF 攻击的方法包括对用户输入进行验证，禁止访问内部网络上的地址，以及实施严格的访问控制。
![img.png](img.png)

使用的服务中有以下功能：
- 通过URL地址分享内容
- 通过URL地址把原地址的网页内容调优使其适合手机屏幕浏览（转码功能）
- 通过 URL 地址翻译对应文本的内容，即类似 Google 的翻译网页功能
- 通过 URL 地址加载或下载图片，即类似图片抓取功能
- 以及图片、文件抓取收藏功能

如图片抓取功能
```javascript
const response = await axios({
method: 'get',
responseType: 'arraybuffer',
url
})
ctx.body = response.data;
ctx.set(response.headers);
```

但是，如果调用时，传入了一个内网地址。就可以从外网，非法访问内网。如果应用程序对用户提供的URL和远端服务器返回的信息没有进行合适的验证和过滤，就会存在这种服务端请求伪造的缺陷，即 Server-Side Request Forgery，简称 SSRF。

# 危害
攻击者可以利用 SSRF 实现的攻击主要有 5 种：

- 可以对外网、服务器所在内网、本地进行端口扫描，获取一些服务的 Banner 信息
- 攻击运行在内网或本地的应用程序（比如溢出）
- 对内网 Web 应用进行指纹识别，通过访问默认文件实现
- 攻击内外网的 Web 应用，主要是使用 GET 参数就可以实现的攻击
- 利用 file 协议读取服务器文件

最后一条的防御，需要对协议做判断。

# 防护思路

防止SSRF漏洞：

- 对外部输入进行过滤和验证，以确保它们是有效的。
- 使用安全的库和框架，这些库和框架可以帮助您防止SSRF漏洞。
- 避免将用户提供的数据用于构造URL。
- 限制可以访问的网络范围。
# 解决方案
- 要堵住这个漏洞，关键在于验证用户输入的网址，特别是网址解析后的IP地址。
- 解决方案：解析用户提交的网址得到IP，对于短链接或http://xip.io等代理服务生成的IP必须跟踪解析，然后屏蔽内网IP段。
  - 解析目标 URL, 获取 scheme、host（推荐使用系统内置函数完成,避免自己使用正则提取）
  - 检查 scheme 是否为合法 (如非特殊需求请只允许 http 和 https)
  - 解析 host 获取 dns 解析后的 IP 地址
  - 检查解析后的 IP 地址是否为外网地址，过滤掉内网地址
  - 请求经过解析后的 IP 地址
使用解析后的 IP 地址替换 host 请求、禁用 Redirect 跟踪：
    如果最后一步直接传入URL直接请求,会导致再次进行DNS解析,通过 [DNS Rebinding](https://zh.wikipedia.org/wiki/DNS%E9%87%8D%E6%96%B0%E7%BB%91%E5%AE%9A%E6%94%BB%E5%87%BB) 有概率绕过 IP 地址检查从而访问内网 IP 地址.请求需要禁用 Redirect 跟踪, 如有需要跟踪 Redirect 的需求, 需再次判断 scheme、host 解析、IP 地址。保证真正请求的是经过过滤的ip地址，即可。

# 代码示例

首先要禁用掉非http(s)协议，如果判断出请求来源协议不为http(s)，则中断请求。

其次要禁用内网地址。如10，192，127开头的ip地址。这里过滤地址不要直接通过正则匹配请求地址，要通过dns查询来源域名；将所有的域名最终转换为ip，就是不管参数是ip还是域名，最终都要判断即将请求的ip地址，并过滤内网ip。同时，对dns查询错误做出处理。将所有的链接都转为ip处理。这样做的好处有，可以有效防御短连接绕过；DNS重绑绕过。



具体ip地址过滤代码如下：

```javascript
function ipIsPrivate(addr) {
  return /^(::f{4}:)?10\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/i
 .test(addr) ||
  /^(::f{4}:)?192\.168\.([0-9]{1,3})\.([0-9]{1,3})$/i.test(addr) ||
  /^(::f{4}:)?172\.(1[6-9]|2\d|30|31)\.([0-9]{1,3})\.([0-9]{1,3})$/i
 .test(addr) ||
  /^(::f{4}:)?127\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/i.test(addr) ||
  /^(::f{4}:)?169\.254\.([0-9]{1,3})\.([0-9]{1,3})$/i.test(addr) ||
  /^f[cd][0-9a-f]{2}:/i.test(addr) ||
  /^fe80:/i.test(addr) ||
  /^::1$/.test(addr) ||
  /^::$/.test(addr);
}
```

```javascript
const protocolAndDomainRE = /https?:/i

const localhostDomainRE = /^localhost[\:?\d]*(?:[^\:?\d]\S*)?$/
const nonLocalhostDomainRE = /^[^\s\.]+\.\S{2,}$/

```


dns查询错误处理  如果查询错误的ip，统一认为处理为内网地址：



```javascript
const axios = require('axios');
const dns = require('dns')
const { parse } = require('url')
function getHostByName (domain) {
  return new Promise((resolve, reject) => {
      dns.lookup(domain, (err, address, family) => {
          if(err) {
              reject(err)
          }
          resolve(address)
      })
  })
}

const ssrfSolution = async function () {
  // 判断内网ip
 let host
  try {
    host = await getHostByName(hostname)
  } catch (err) {
    host = '127.0.0.1' // 如果dns解析失败，则内网ip处理，返回错误
 }
  if(ctx.helper.ipIsPrivate(host)) {
    return true
 } else{
    return false
 }
}
```


```javascript
// 完整node.js端代码示例

const axios = require('axios');
const dns = require('dns')
const { parse } = require('url')
const parseFunc = require('url-parse')
const ssrfAgent = require('ssrf-agent')
const urllib = require('urllib')
const isReservedIp = require('martian-cidr').default

// const protocolAndDomainRE = /^(?:https?:)?\/\/(\S+)$/

const protocolAndDomainRE = /https?:/i

const localhostDomainRE = /^localhost[\:?\d]*(?:[^\:?\d]\S*)?$/
const nonLocalhostDomainRE = /^[^\s\.]+\.\S{2,}$/

module.exports = app => {
    return class DelegateController extends app.Controller {
        async delegate() {
            const { ctx, service, config, logger } = this;
            const url = ctx.query.url;
            const { protocol, hostname } = parse(url);
            try {
                ctx.validate({
                        url: "string"
                    },
                    ctx.query
                );
            } catch (err) {
                ctx.body = {
                    retCode: config.RetCode.ERROR_PARAMETER.code,
                    errMsg: err.errors
                };
                return false;
            }

            /**
             * 根据域名获取 IP 地址
             * @param {string} domain
             */
            function getHostByName(domain) {
                return new Promise((resolve, reject) => {
                    dns.lookup(domain, (err, address, family) => {
                        if (err) {
                            reject(err)
                        }
                        resolve(address)
                    })
                })
            }

            /**
             * @param {string} host
             * @return {array} 包含 host、状态码
             *
             * 验证 host ip 是否合法
             * 返回值 array(host, value)
             * 禁止访问 0.0.0.0/8，169.254.0.0/16，127.0.0.0/8，240.0.0.0/4 保留网段
             * 若访问 10.0.0.0/8，172.16.0.0/12，192,168.0.0/16 私有网段，标记为 PrivIp 并返回
             */

            function isValidataIp(host) {
                if ((ip.isV4Format(host) || ip.isV6Format(host)) && !isReservedIp(host)) {
                    if (ip.isPrivate(host)) {
                        return [host, 'PrivIp']
                    } else {
                        return [host, 'WebIp']
                    }
                } else {
                    return false
                }
            }


            //  主逻辑
            // 判断协议
            if (!protocolAndDomainRE.test(protocol)) {
                return ctx.body = {
                    retCode: 50006,
                    errMsg: 'Invalid Request Url!'
                };
            }
            // 判断ip
            const ssrfSolution = async function () {
                // 判断内网ip
                let host
                try {
                    host = await getHostByName(hostname)
                } catch (err) {
                    host = '127.0.0.1' // 如果dns解析失败，则当作内网ip处理，返回错误
                }
                if (ctx.helper.ipIsPrivate(host) || isReservedIp(host)) {
                    return true
                } else {
                    return false
                }
            }
            let res = await ssrfSolution(url)
            if (res) {
                ctx.body = {
                    retCode: 50006,
                    errMsg: 'Invalid Request Url!'
                };
            } else {
                // const response = await axios({
                //     method: 'get',
                //     responseType: 'arraybuffer',
                //     url
                //   })
                const response = await urllib.request(url, {
                    method: 'get',
                    maxRedirects: 0
                })

                const contentType = response.headers["content-type"]

                if (contentType == "image/jpeg" || contentType == "image/jpg" || contentType == "image/png" || contentType == "video/mp4") {
                    ctx.body = response.data;
                    ctx.set(response.headers);
                } else {
                    ctx.body = {
                        retCode: 50006,
                        errMsg: 'Invalid Request Url!'
                    };
                }
            }
        }
    };
};

```

# 名词解释
### 短链接绕过
   大部分情况下这样处理是没有问题的，不过攻击者可不是一般人。这里存在一个两个可以绕过的方式，首先是短链接，短链接是先到短链接服务的地址之后再302跳转到真实服务器上，如果攻击者对内网地址进行短链处理之后以上代码会判断短链服务的 IP 为合法 IP 而通过校验。
   针对这种绕过方式，我们有两种方法来阻止：
1. 直接根据请求返回的响应头中的 HOST 来做内网 IP 判断
2. 由于跳转后的地址也还是需要 DNS 解析的，所以只要在每次域名请求 DNS 解析处都做内网 IP 判断的逻辑即可

### DNS 重新绑定绕过
   DNS如何重新绑定的工作
   攻击者注册一个域名（如attacker.com），并在攻击者控制下将其代理给DNS服务器。 服务器配置为很短响应时间的TTL记录，防止响应被缓存。 当受害者浏览到恶意域时，攻击者的DNS服务器首先用托管恶意客户端代码的服务器的IP地址作出响应。 例如，他们可以将受害者的浏览器指向包含旨在在受害者计算机上执行的恶意JavaScript或Flash脚本的网站。
   恶意客户端代码会对原始域名（例如attacker.com）进行额外访问。 这些都是由同源政策所允许的。 但是，当受害者的浏览器运行该脚本时，它会为该域创建一个新的DNS请求，并且攻击者会使用新的IP地址进行回复。 例如，他们可以使用内部IP地址或互联网上某个目标的IP地址进行回复。
   via: [《DNS 重新绑定攻击》](https://zh.wikipedia.org/zh-hans/DNS%E9%87%8D%E6%96%B0%E7%BB%91%E5%AE%9A%E6%94%BB%E5%87%BB)
   简单来说就是利用 DNS 服务器来使得每次解析返回不同的 IP，当在校验 IP 的时候 DNS 解析返回合法的值，等后续重新请求内容的时候 DNS 解析返回内网 IP。这种利用了多次 DNS 解析的攻击方式就是 DNS 重新绑定攻击。

由于 DNS 重新绑定攻击是利用了多次解析，所以我们最好将校验和抓取两次 DNS 解析合并成一次，这里我们也有两种方法来阻止：
1. 将第一次 DNS 解析得到的 IP 直接用于第二次请求的 DNS 解析，去除第二次解析的问题
2. 在抓取请求发起的时候直接判断解析的 IP，如果不符合的话直接拒绝连接。


# Reference

[Server-Side Request Forgery](https://www.yuque.com/liyuan-pea35/oscp/dhrgci)
