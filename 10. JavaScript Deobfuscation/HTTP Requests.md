### cURL Basics
1. **Basic GET Request**:
   To fetch a webpage’s content, we simply specify the URL with `curl`:
   ```bash
   curl http://SERVER_IP:PORT/
   ```

   Example Output:
   ```html
   </html>
   <!DOCTYPE html>

   <head>
       <title>Secret Serial Generator</title>
       ...
       <h1>Secret Serial Generator</h1>
       <p>This page generates secret serials!</p>
   </div>
   </body>
   </html>
   ```

   This output matches what we saw when inspecting the page source earlier.

2. **Basic POST Request**:
   To send a `POST` request (similar to what the `generateSerial` function does), we can use the `-X POST` flag:
   ```bash
   curl -s http://SERVER_IP:PORT/ -X POST
   ```

   Here, the `-s` option (silent mode) is used to suppress progress and error messages, displaying only the response content.

3. **POST Request with Data**:
   Typically, `POST` requests include data sent in the request body. For this, we add the `-d` option to specify data parameters:
   ```bash
   curl -s http://SERVER_IP:PORT/ -X POST -d "param1=sample"
   ```

### Next Steps
In the following section, we’ll simulate the exact `POST` request to `/serial.php` as defined in `generateSerial`. Although this function does not send data, we can use `cURL` to explore possible responses from the server, gaining further insights into the endpoint’s functionality.