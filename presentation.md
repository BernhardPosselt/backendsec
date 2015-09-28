title: Backend Security
theme: sjaakvandenberg/cleaver-light
--
# Backend Security

--

### OWASP TOP 10 2013

1. **Injection**
2. **Broken Authentication and Session Management**
3. Cross-Site Scripting (XSS)
4. Insecure Direct Object References
5. Security Misconfiguration
6. Sensitive Data Exposure
7. Missing Function Level Access Control
8. **Cross-Site Request Forgery (CSRF)**
9. Using Known Vulnerable Components
10. **Unvalidated Redirects and Forwards**

--

### What Will Be Covered

* Shell Injection
* Directory Traversal
* Host Header Poisoning
* Unvalidated Redirects
* Session hijacking
* XXE
* CSRF
* Timing Attacks
* Password Hashing

--

### Shell Injection

```java
@RequestMapping("/")
public ModelAndView listFiles(@RequestParam("fileName") String fileName) {
  if (fileName.startsWith("/a/valid/directory")) {
    Runtime.getRuntime().exec("cat " +  fileName);
  }
}
```

* **GET** /?fileName=/a/valid/directory;rm -rf /

  **cat /a/valid/directory**

  **rm -rf /**

```java
Runtime.getRuntime().exec(new String[]{"cat", fileName});
```

**Same applies to LDAP, SMB, SQL!**

--

### Directory Traversal

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
fileName = (new File(fileName)).getCanonicalPath();

if (fileName.startsWith("/a/valid/directory")) {
  Runtime.getRuntime().exec(new String[]{"cat", fileName});
}
```
--

### Host Header Poisoning

```java
@RequestMapping("/reset-password")
public void resetPasswordEmail(HttpServletRequest request, @RequestParam("email") String email) {
  String resetUrl = request.getRequestURL().toString() + "?" + request.getQueryString();
  String message = "Please go to " + resetUrl + " and enter a new password";
  Mail.send(email, message)
}
```

* **POST** /reset-password
* **HOST**: mydomain.com

```
if (resetUrl.startsWith("https://mydomain.com"))
```

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

CSRF token

```xml
<input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"/>
```
or
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
