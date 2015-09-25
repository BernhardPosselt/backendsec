title: Backend Security
theme: sjaakvandenberg/cleaver-light
--
# Backend Security

--

### What This Talk Is Not About


* Sql Injection
* HTML/JavaScript/CSS related attacks like XSS

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

### Resources
* [OWASP Top 10](https://www.owasp.org/index.php/Top_10_2013-Top_10)
