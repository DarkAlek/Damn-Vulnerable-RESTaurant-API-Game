## Write-up for Changes Made to Fix Security Vulnerabilities

### Overview
The Flask Python app for Damn Vulnerable RESTaurant had multiple critical security vulnerabilities that needed fixing. Below is a detailed write-up of the changes made to address these vulnerabilities and improve the overall security of the application.

### 1. Technology Details Exposed Via HTTP Header

#### Issue:
The `/healthcheck` endpoint was exposing technology details through the `X-Powered-By` HTTP header, potentially giving attackers information about the Python and FastAPI versions used.

#### Fix:
The header was removed by commenting out the line that added it in `apis/healthcheck/service.py`.

#### Code Change:
```python
# response.headers["X-Powered-By"] = "Python 3.8, FastAPI ^0.103.0"
```

### 2. Unrestricted Menu Item Deletion

#### Issue:
The `/menu/{id}` endpoint allowed anyone to delete menu items without any authorization checks.

#### Fix:
Added authorization checks to ensure only users with the roles `EMPLOYEE` or `CHEF` can delete menu items. This was implemented using `Depends(RolesBasedAuthChecker(...))` in the `delete_menu_item` function in `apis/menu/service.py`.

#### Code Change:
```python
auth=Depends(RolesBasedAuthChecker([UserRole.EMPLOYEE, UserRole.CHEF])),
```

### 3. Unrestricted Profile Update (IDOR)

#### Issue:
Users could update any profile by providing the username in the HTTP request to the `/profile` endpoint with the PUT method, leading to an Insecure Direct Object Reference (IDOR) vulnerability.

#### Fix:
Ensured that the `current_user` can only update their own profile by comparing the username in the token with the username in the request.

#### Code Change:
```python
if current_user.username != db_user.username:
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="You do not have access to this page",
        headers={"WWW-Authenticate": "Bearer"},
    )
```

### 4. Privilege Escalation

#### Issue:
Users could escalate their privileges to `EMPLOYEE` by simply changing the role through the `/users/update_role` endpoint.

#### Fix:
Restricted role updates to only users who already have `EMPLOYEE` or `CHEF` roles, preventing unauthorized privilege escalation.

#### Code Change:
```python
auth=Depends(RolesBasedAuthChecker([models.UserRole.EMPLOYEE, models.UserRole.CHEF]))
```

### 5. Server Side Request Forgery (SSRF)

#### Issue:
The PUT `/menu` endpoint allowed setting image URLs, which could be exploited to perform SSRF attacks.

#### Fix:
Implemented domain whitelisting and content type checks to ensure only valid image URLs from trusted domains can be used.

#### Code Change:
```python
parsed_url = urlparse(image_url)
domain = parsed_url.netloc
allowed_domains = ["localhost"] # allowed domains for images download
if domain not in allowed_domains:
    raise HTTPException(status_code=500, detail="Error!")
valid_extensions = (".jpg", ".jpeg", ".png", ".gif", ".bmp")
if not parsed_url.path.lower().endswith(valid_extensions):
    raise HTTPException(status_code=500, detail="Error!")
response = requests.get(image_url)
content_type = response.headers.get("content-type", "")
if not content_type.startswith("image"):
    raise HTTPException(status_code=500, detail="Error!")
```

### 6. Remote Code Execution (RCE)

#### Issue:
The `/admin/stats/disk` endpoint was vulnerable to command injection through the `parameters` query parameter, allowing arbitrary command execution on the server.

#### Fix:
Validated and sanitized the `parameters` input by passing it as a list of arguments to the `subprocess.run` function, rather than concatenating it into a shell command.

#### Code Change:
```python
# command = "df -h " + parameters
command = ["df", "-h"]
if parameters:
    command.extend(parameters.split())
# result = subprocess.run(
#     command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True
# )
result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
```

### 7. Root Access via Insecure Sudo Configuration

#### Issue:
A misconfigured Dockerfile allows the `find` command to be run with root permissions via sudo without a password. This introduces a significant security risk, especially when combined with other vulnerabilities in the application.

#### Exploit Chain:

1. **SSRF Attack to Reset Admin Password:**
   - The PUT `/menu` endpoint allows setting image URLs, which can be exploited to perform a Server Side Request Forgery (SSRF) attack.
   - Use the SSRF vulnerability to access the `/admin/reset-chef-password` endpoint from localhost, resetting the Chef's password and gaining admin access.

2. **Privilege Escalation:**
   - Once logged in as Chef, use the escalated privileges to access the `/admin/stats/disk` endpoint, which executes system commands.

3. **Command Injection via `/admin/stats/disk`:**
   - Exploit the command injection vulnerability in the `parameters` query parameter of the `/admin/stats/disk` endpoint.
   - Execute the `whoami` command to confirm root access by performing request with admin bearer token and encoded url.

Example Url: 
   ```text
   http://localhost:8080/admin/stats/disk?parameters=%26%26%20sudo%20find%20.%20-exec%20whoami%20%5C%3B
   ```

#### Fix:

**Dockerfile Configuration:**
   - Remove the insecure sudo configuration for the `find` command in the Dockerfile to prevent running it with root permissions.


### Conclusion
By combining the vulnerabilities related to SSRF, privilege escalation, and command injection, an attacker can achieve root access to the server. This underscores the importance of addressing each vulnerability comprehensively and ensuring secure configurations to prevent exploitation. Removing the insecure sudo configuration and sanitizing inputs are critical steps in securing the application.