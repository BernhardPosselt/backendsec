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


```
POST /reset-password HTTP/1.1
Host: myattackdomain.com
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
  .filter(allowedDomain -> request.getRequestURL().startsWith(allowedDomain))
  .findAny()
  .orThrow(new HttpForbiddenException());
```

**PHP**:
```php
$validDomains = ["myshopdomain.com", "192.168.0.1"];

if (count(array_filter($validDomains, function () {
  return strpos($_SERVER['HTTP_HOST'], $validDomains) === 0;
})) === 0) {
  throw new HttpForbiddenException();
}
```

--

### Cache Poisoning

http://www.skeletonscribe.net/2013/05/practical-http-host-header-attacks.html

--

### Unvalidated Redirects

```java
@RequestMapping("/redirect")
public void redirectTo(@RequestParam("url") String toUrl) {
  return "redirect:" + toUrl;
}
```

* **GET** /redirect?toUrl=http://myfakeshop.com

```java
if (toUrl.startsWith("https://known.com"))
```

--

### Session hijacking

Generally covered by framework

* **GET** /some-url?session_id=1234kj123k12323

* https://myshop.com/login?session_id=1234kj123k12323

More on [https://www.owasp.org/index.php/Session_Management_Cheat_Sheet](https://www.owasp.org/index.php/Session_Management_Cheat_Sheet)

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
