## How would you implement a secure login field on a high traffic website where performance is a consideration

-TLS is a must to provide confidentiality and integrity
-Input validation to avoid SQLI and XSS
-Single Sigon on systems that are trusted by the community
-Brute force protection (captchas or MFA, time based lock out)
-Password complexity

## What are the various ways to handle account brute forcing

-Account lockouts
-IP restrictions
-Fail2ban
-MFA
-Unique login URLS
-Monitor server logs

## What is Cross Site Rquest Forgery (CSRF)

CSRF is an attack that forces an end user to execute an unwanted actions on a web application in which they're currently authenticated.
With a little help of social engineering an attacker may trick the users of a web application into executing actions of the attacker's choosing. If the victim is a normal user, a successful CSRF attack can force the user to perform site changing requets like transferring finds, chainging their email address, etc...

Conditions
-Relevant action by user
-Cookie session handling
-Attacker can easily determine the values of the request parameters needed to perform action

With these conditions in place, the attacker can construct a web page containing the following HTML:

<html>
  <body>
    <form action="https://vulnerable-website.com/email/change" method="POST">
      <input type="hidden" name="email" value="pwned@evil-user.net" />
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>

## How to Prevent CSRF Attachks

-Include CSRF Toekns within relevant requests
-Use SameSite Cookie Attribute
-Do not use GET requests for state changing operations
-Verify Origin with Standard headers

## If you were a site administrator looking for incoming CSRF attacks, what would you look for?

Did we already implement CSRF tokens?
Did we already have controls in place?

## Whats the difference between HTTP and HTML

HTML - Markup language
HTTP - Networking/Application protocol

## How does HTTP Handle State

Even though multiple requests can be sent over the same HTTP connection the server does not attach any meaning. As far as HTTP is concerned they are all still separate requests and must contain enough information on their own to fulfill the request. That is the essence of "statelessness"

Requests will not be associated with each other absent some shared info the server knows about which is where cookies come in

## Cookie vs Token

Cookie 
- Stateful 
- Session is kept client AND server side
1. Users enters their login credentials
2. Server verifies the credentials and creates session which is stored in a database
3. A cookie with the session ID is placed in the users browser
4. On subsequent requests, the session ID is verified against the database and if valid the request is processed
5. Once a user logs out of the app, the session is destroyed both client-side AND server-side


Token 
- Stateless
- Generally meant Json Web Tokens (JWT)
- Server does NOT keep a record of which users are logged in or which JWTs have been issued. Instead, every request to the server is accompanied by a token which the server uses to verify the authenticity of the request
1. Users enters their login credentials
2. Server verifies the credentials are correct and returns a signed token
3. This token is stored client side, most commonly in local storage but can be stored in session storage or a cookie as well
4. Subsequent requests to the server include this token as an additional Authorization header or through one of the other methods mentioned above
5. The server decodes the Json Web Token and if the token is valid processes the request
6. Once a user logs out, the token is destoryed client-side

## What is XSS? Types?

Cross Site Scripting attacks are a type of injection in which malicious scripts are injected into a web browser on a web application

Stored - Injected script is stored on the target server in a database, message form, comment field, etc...
Reflected - Injected script is reflected off the web server such as in an error message, search result, etc..
DOM - Injected payload modifies the DOM in the victims browser used by the original client side script so that the client code run in an unexpected manner

## What are the common defenses against XSS?

Input validation and Output Sanitization

## What is an open redirect vulnerability

An Open redirect is when a web application or server uses an unvalidated user submitted link to redirect the user to a given website or page

## Which cookie security flags exist

HTTPOnly
Secure Flag
SameSite

## Common file upload restrictions

-Insert Nullbyte %x20
-Add double extension rev.php.php
-CamelCase rev.pHp

## What is SQL Injection

SQL Injection is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. It generally allows an attackers 
to view data that they are not normally able to retrieve.

## How to prevent SQL Injection

Most instances of SQL Injection can be prevented by using parameterized queries instead of string concatenation within the query

The following code is vulnerable to SQL injection because the user input is concatenated directly into the query:

String query = "SELECT * FROM products WHERE category = '"+ input + "'";

Statement statement = connection.createStatement();

ResultSet resultSet = statement.executeQuery(query);

This code can be easily rewritten in a way that prevents the user input from interfering with the query structure:

PreparedStatement statement = connection.prepareStatement("SELECT * FROM products WHERE category = ?");

statement.setString(1, input);

ResultSet resultSet = statement.executeQuery();

## What is XXE and how the payloads work

XML External entity injection is a web security vulnerability that allows to interfere with an applicatios processing of XML data. It often allows an attacker to view files on the 
application server filesystem, and to interact with any backend or external systems that the application itself can access

In some situations an attacker can escalate an XXE attack to compromise the underlying server or other backend infrastructure to perform SSRF attacks

For example, suppose a shopping application checks for the stock level of a product by submitting the following XML to the server:

<?xml version="1.0" encoding="UTF-8"?>
<stockCheck><productId>381</productId></stockCheck>

The application performs no particular defenses against XXE attacks, so you can exploit the XXE vulnerability to retrieve the /etc/passwd file by submitting the following XXE payload:

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>

This XXE payload defines an external entity &xxe; whose value is the contents of the /etc/passwd file and uses the entity within the productId value. This causes the application's response to include the contents of the file:

Invalid product ID: root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin

DOS attack with Billion Laughs Attack

## How to prevent XEE

Disable resolution of external entities and disable support for XInclude. Config for safer XML parsing.