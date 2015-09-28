title: Web-Security
theme: sjaakvandenberg/cleaver-light
--
# Web-Security

--

### OWASP TOP 10 2013

1. **Injection**
2. **Broken Authentication and Session Management**
3. **Cross-Site Scripting (XSS)**
4. Insecure Direct Object References
5. Security Misconfiguration
6. Sensitive Data Exposure
7. Missing Function Level Access Control
8. **Cross-Site Request Forgery (CSRF)**
9. Using Known Vulnerable Components
10. **Unvalidated Redirects and Forwards**

--

### What Will Be Covered

* Injection
* Directory Traversal
* Host Header Poisoning
* Cache Poisoning
* Unvalidated Redirects
* Clickjacking
* XSS
* Session hijacking
* File Upload
* XXE
* CSRF
* Timing Attacks
* Password Hashing

--

### Shell Injection Vulnerability

```java
@RequestMapping("/")
public ModelAndView listFiles(@RequestParam("fileName") String fileName) {
  if (fileName.startsWith("/a/valid/file")) {
    Runtime.getRuntime().exec("cat " +  fileName);
  }
}
```

--

### Shell Injection Attack

```java
@RequestMapping("/")
public ModelAndView listFiles(@RequestParam("fileName") String fileName) {
  if (fileName.startsWith("/a/valid/file")) {
    Runtime.getRuntime().exec("cat " +  fileName);
  }
}
```

* **GET** /?fileName=/a/valid/file;rm -rf /

```java
Runtime.getRuntime().exec("cat /a/valid/file; rm -rf /");
```

--

### Shell Injection Prevention

**Better but vulnerable to directory traversal (next slide)**

**Java**:

```java
Runtime.getRuntime().exec(new String[]{"cat", fileName});
```

**PHP**:

```php
shell_exec("cat " . escapeshellarg($_GET['fileName']));
```

* **Same applies to LDAP, SMB, SQL!**
* **Beware of combinations**, e.g. executing SMB commands on the command line


--

### Directory Traversal Vulnerability

```java
@RequestMapping("/")
public ModelAndView listFiles(@RequestParam("fileName") String fileName) {
  if (fileName.startsWith("/a/valid/directory")) {
    Runtime.getRuntime().exec(new String[]{"cat", fileName});
  }
}
```


--

### Directory Traversal Attack

```java
@RequestMapping("/")
public ModelAndView listFiles(@RequestParam("fileName") String fileName) {
  if (fileName.startsWith("/a/valid/directory")) {
    Runtime.getRuntime().exec(new String[]{"cat", fileName});
  }
}
```

* **GET** /?fileName=/a/valid/directory/../../../etc/passwd
* **GET** /?fileName=\\a\\valid\\directory\\..\\..\\..\\sensitive.file

```java
Runtime.getRuntime().exec(new String[]{"cat", "/a/valid/directory/../../../etc/passwd"});
```

--

### Directory Traversal Prevention

**Java**:

```java
fileName = (new File(fileName)).getCanonicalPath();
if (fileName.startsWith("/a/valid/directory")) {
  // etc
}
```

**PHP**:

```php
$path = realpath($_GET['fileName']);  // attention: crashes when path does not exist, use a lib
if (strpos($path, "/a/valid/directory") === 0) {
  // etc
}
```

--

### Host Header Poisoning Vulnerability

```java
@RequestMapping("/reset-password")
public void resetPasswordEmail(HttpServletRequest request, @RequestParam("email") String email) {
  String resetUrl = request.getRequestURL().toString() + "/new-password";
  String message = "Please go to " + resetUrl + " and enter a new password";
  Mail.send(email, message)
}
```

--

### Host Header Poisoning Attack
```java
@RequestMapping("/reset-password")
public void resetPasswordEmail(HttpServletRequest request, @RequestParam("email") String email) {
  String resetUrl = request.getRequestURL().toString() + "/new-password";
  String message = "Please go to " + resetUrl + " and enter a new password";
  Mail.send(email, message)
}
```

```http
POST /reset-password HTTP/1.1
Host: myattackdomain.com
```

```http
POST /reset-password HTTP/1.1
Host: valid-domain.com
Host: myattackdomain.com
```

```http
POST /reset-password HTTP/1.1
Host: valid-domain.com:@myattackdomain.com
```

```http
POST /reset-password HTTP/1.1
Host: valid-domain.com
X-Forwarded-Host: myattackdomain.com
```

```java
String message = "Please go to http://myattackdomain.com/new-password and enter a new password";
```

--

### Host Header Poisoning Prevention
Middleware approach:

**Java**:
```java
Collection<String> validDomains = Arrays.asList("myshopdomain.com", "192.168.0.1");

validDomains.stream()
  .filter(allowedDomain -> request.getServerName().equals(allowedDomain))
  .findAny()
  .orThrow(new HttpForbiddenException());
```

**PHP**:
```php
$validDomains = ["myshopdomain.com", "192.168.0.1"];

if (count(array_filter($validDomains, function ($validDomain) {
  return $_SERVER['HTTP_HOST'] === $validDomain;
})) === 0) {
  throw new HttpForbiddenException();
}
```

--

### Cache Poisoning Attack
**Similar to Host Header Poisoning**

Joomla used to generate HTML templates with absolute URLs:

```
GET / HTTP/1.1
Host: cow"onerror='alert(1)'rel='stylesheet'
```

```xml
<link href="http://cow"onerror='alert(1)'rel='stylesheet'/" rel="canonical"/>
```

--

### Cache Poisoning Prevention

**Depends on your Cache Setup**

More information on [http://www.skeletonscribe.net/2013/05/practical-http-host-header-attacks.html](http://www.skeletonscribe.net/2013/05/practical-http-host-header-attacks.html)

--

### Unvalidated Redirects Vulnerability

```java
@RequestMapping("/redirect")
public void redirectTo(@RequestParam("url") String toUrl) {
  return "redirect:" + toUrl;
}
```

--

### Unvalidated Redirects Attack

```java
@RequestMapping("/redirect")
public void redirectTo(@RequestParam("url") String toUrl) {
  return "redirect:" + toUrl;
}
```

```http
GET /redirect?url=http://myfakeshop.com
```

```http
GET /redirect?url=http://valid-shop.com:@myfakeshop.com
```

```java
return "redirect:http://valid-shop.com:@myfakeshop.com";
```

--

### Unvalidated Redirects Prevention

**Java**:
```java
@RequestMapping("/redirect")
public void redirectTo(@RequestParam("url") String toUrl) {
  if (toUrl.equals("http://valid-domain.com/the/url")) {
    return "redirect:" + toUrl;
  }
}
```

**PHP**:
```php
if ($_GET['url'] === 'http://valid-domain.com/the/url') {
  header('Location: ' . $_GET['url']);
  exit;
}
```

--

### Clickjacking Attack

Invisible IFrame + CSS magic which redirects clicks to target website

[![IMAGE ALT TEXT HERE](http://img.youtube.com/vi/3mk0RySeNsU/0.jpg)](http://www.youtube.com/watch?v=3mk0RySeNsU)

--

### Clickjacking Prevention
Middleware approach, more options (**DENY**, **SAMEORIGIN**, **ALLOW-FROM uri**)

**Java**:
```java
HttpservletResponse response;
response.setHeader('X-Frame-Options', 'DENY');
```

**PHP**:
```php
header('X-Frame-Options: DENY')
```
--

### XSS Vulnerability
PHP examples this time (I'm not that familiar with JSP)

```php
<input type="text" value="<?php echo $accountId ?>"/>
```

```php
<?php echo $accountId ?>
```

```php
<script>var accountId = <?php echo $accountId ?>;</script>
```

```php
<<?php echo $accountId ?>>
```

--

### XSS Attack

**$accountId = "\" /> &lt;script&gt;alert('hi')&lt;/script&gt;<img src=\""**

```php
<input type="text" value="" /> <script>alert('hi')</script><img src=""/>
```

**$accountId = "&lt;script&gt;alert('hi')&lt;/script&gt;"**

```php
<script>alert('hi')</script>
```
**$accountId = '0; window.location = "http://attacker.com"'**

```php
<script>var accountId = 0; window.location = "http://attacker.com"; </script>
```

**$accountId = "a>&lt;script&gt;alert('hi')&lt;/script";**

```php
<a><script>alert('hi')</script>
```

--

### Lesser Known XSS Vulnerabilities
**href**, **src**, **style** and **&lt;style&gt;** allow javascript:alert('hi')

```php
<a href="<?php echo $accountId>">link</a>
```

```php
<a href="/?value=<?php echo $accountId>">link</a>
```

```php
<!-- <?php echo $comment ?> -->
```

```php
<img src="<?php echo $accountId>"/>
```

```php
<img style="<?php echo $accountId>"/>
```

```php
<style><?php echo $accountId></style>
```

```javascript
$('<a>').html(response);  // use text() instead
```

**Content-Type: text/html; charset=utf-8** for JSON responses

--

### XSS Prevention

* Escape based on usage
* Validate URIs for **src** and **href**
* Do not use dynamic CSS style sheets
* [Consult the prevention sheet](https://www.owasp.org/index.php/XSS_%28Cross_Site_Scripting%29_Prevention_Cheat_Sheet#XSS_Prevention_Rules_Summary), too much possibilities
* Use [CSP](https://developer.mozilla.org/en-US/docs/Web/Security/CSP)

--

### Session hijacking

Generally covered by framework

* **GET** /some-url?session_id=1234kj123k12323

* https://myshop.com/login?session_id=1234kj123k12323

More on [https://www.owasp.org/index.php/Session_Management_Cheat_Sheet](https://www.owasp.org/index.php/Session_Management_Cheat_Sheet)

--

### File Upload Vulnerability

```php
if(preg_match('~^[a-z_\.0-9]+\.(jp[e]?g|png|gif)$~i', $filename)) {
    require($filename);
}
```

```php
if (in_array($_FILES["file"]["type"], ["image/gif", "image/png"])) {
    $destination = "uploads/" . $_FILES["file"]["name"];
    move_uploaded_file($_FILES["file"]["tmp_name"], $destination);
}
```

```php
include($_GET['navigation'] '.php');
```

```php
if (@getimagesize($_FILES["file"]["tmp_name"]) !== false) {
    $destination = "uploads/" . $_FILES["file"]["name"];
    move_uploaded_file($_FILES["file"]["tmp_name"], $destination);
}
```


--

### File Upload Attack

```php
if(preg_match('~^[a-z_\.0-9]+\.(jp[e]?g|png|gif)$~i', $filename)) {
    require($filename);
}
```
Upload an image which embeds php tags (<?php ?>)

```php
if (in_array($_FILES["file"]["type"], ["image/gif", "image/png"])) {
    $destination = "uploads/" . $_FILES["file"]["name"];
    move_uploaded_file($_FILES["file"]["tmp_name"], $destination);
}
```

```http
Content-Type: multipart/form-data; boundary=----ThisIsABoundary

 ------ThisIsABoundary
Content-Disposition: form-data; name="file"; filename="evil.php"
Content-Type: image/jpeg

<?php phpinfo();
 ------ThisIsABoundary--
```

```php
include($_GET['id'] '.php');
```

```
GET /?id=myuploaded.php
```

--

### File Upload Attack 2

```php
if (@getimagesize($_FILES["file"]["tmp_name"]) !== false) {
    $destination = "uploads/" . $_FILES["file"]["name"];
    move_uploaded_file($_FILES["file"]["tmp_name"], $destination);
}
```

Embed comment in jpeg

```php
<?php do_something_evil(); __halt_compiler();
```

Parser stops before parsing garbage image data

--

### File Upload Prevention

* Do not execute anything from the upload directory
* Do not require/include anything from the upload directory
* Disallow special files (.htaccess, [.user.ini](http://php.net/manual/en/configuration.file.per-user.php), web.config, robots.txt, crossdomain.xml, clientaccesspolicy.xml) and turn off .htaccess parsing
* Remove executable bits from uploads (644)
* Set the correct content type when serving the file
* Disallow SVG (JavaScript can be embedded) and HTML
* Use a separate static content server and domain
* [http://nullcandy.com/php-image-upload-security-how-not-to-do-it/](http://nullcandy.com/php-image-upload-security-how-not-to-do-it/)
--

### XXE

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [  
 <!ELEMENT foo ANY >
 <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>
```

* Disable XML External Entity Processing!

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
FEATURE = "http://xml.org/sax/features/external-general-entities";
dbf.setFeature(FEATURE, false);
```

--

### CSRF

```java
@RequestMapping("/delete-user")
public void deleteUser(@RequestParam("user") String user) {
  if (isAuthenticated()) {
    userService.delete(user)
  }
}
```

Attack via hidden form

```xml
<form action="https://myshop.com/delete-user" method="post">
<input name="user" value="someuser">
</form>
```

Spring: CSRF enforced by default since Spring Security 4.0

```xml
<input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"/>
```
```xml
<meta name="_csrf" content="${_csrf.token}"/>
<meta name="_csrf_header" content="${_csrf.headerName}"/>
```

Beware of CORS with credentials enabled!

--

### Timing Attacks

```java
@RequestMapping("/authenticate")
public void resetPasswordEmail(@RequestParam("user") String user, @RequestParam("pass") String pass) {
  if (user.equals("John") && pass.equals("Passw0rd")) {
    // authenticate user
  }
}
```

* Same applies to database!

```java
if (constantEquals(user, "John") && constantEquals(pass, "Passw0rd")) {
  // authenticate user
}
```

--

### Password Hashing


```java
String password = "mypass";
String hashedPassword = hash(password);
```

Rainbow Tables...

* bcrypt!

```java
String global_salt = BCrypt.gensalt();  // saved in config
String salt = BCrypt.gensalt();  // saved in database with each user
String hashedPassword = BCrypt.hashpw(password, global_salt + salt);
```

--

### Resources
* [OWASP Top 10](https://www.owasp.org/index.php/Top_10_2013-Top_10)
