In analyzing web server traffic, the absence of obvious signs like fuzzing doesn’t guarantee security. Closer inspection, particularly of unusual HTTP headers, can reveal suspicious activity. Common anomalies include:

- **Weird Host Headers**
- **Unusual HTTP Verbs**
- **Modified User Agents**

---

## Finding Strange Host Headers

1. **Filter for HTTP Traffic**: Start by limiting traffic in Wireshark to HTTP requests and responses:
   ```plaintext
   http
   ```

2. **Isolate Irregular Host Headers**: Specify the legitimate server IP to exclude normal traffic. For an external server, substitute with the domain name:
   ```plaintext
   http.request and (!(http.host == "192.168.10.7"))
   ```

### Indicators of Malicious Host Headers

If results appear, examine them for host headers such as `127.0.0.1` or unusual hostnames like `admin`. Attackers often manipulate host headers to escalate privileges using proxy tools like Burp Suite.

**Preventative Measures**:
- Verify **virtualhost** and **access configurations** to prevent unauthorized access.
- Keep the **web server updated**.

---

## Analyzing Code 400s and Detecting Request Smuggling

Error code 400 (Bad Request) can indicate suspicious activity and is useful in identifying malicious HTTP actions.

- **Filter for Code 400 Responses**:
   ```plaintext
   http.response.code == 400
   ```

By following these HTTP streams, you may uncover attempts at request smuggling, also known as **CRLF (Carriage Return Line Feed) Injection**.

### Example CRLF Attempt

An attacker might craft a request like:
```
GET%20%2flogin.php%3fid%3d1%20HTTP%2f1.1%0d%0aHost%3a%20192.168.10.5%0d%0a%0d%0aGET%20%2fuploads%2fcmd2.php%20HTTP%2f1.1%0d%0aHost%3a%20127.0.0.1%3a8080%0d%0a%0d%0a%20HTTP%2f1.1 Host: 192.168.10.5
```

**Decoded by the server**:
```
GET /login.php?id=1 HTTP/1.1
Host: 192.168.10.5

GET /uploads/cmd2.php HTTP/1.1
Host: 127.0.0.1:8080

HTTP/1.1
Host: 192.168.10.5
```

If vulnerable, both requests succeed, allowing unauthorized access. This often results from Apache configurations like:
```plaintext
<VirtualHost *:80>
    RewriteEngine on
    RewriteRule "^/categories/(.*)" "http://192.168.10.100:8080/categories.php?id=$1" [P]
    ProxyPassReverse "/categories/" "http://192.168.10.100:8080/"
</VirtualHost>
```

This type of misconfiguration can leave servers susceptible to CVE-2023-25690, enabling request smuggling.

---

## Monitoring for Successful Exploits

Detecting a **200 (Success)** status code in response to one of these requests confirms an exploit attempt. Regular monitoring of code 400 and code 200 responses is essential in traffic analysis to identify and mitigate adversarial actions.