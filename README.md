# password_pwncheck
Enterprise Password Quality Checking using any hash data sources (HaveIBeenPwned lists, et al)

The purpose of this project is to help companies maintain a stronger password policy without having to jump through too many hoops.  Currently, we support NIST 800-63B features such as testing the password against a long minimum length (default of 15), not matching prev
ious passwords (or similar entries), and most important- the password can't belong to a breach list.

The project consists of two parts:

* A password server -  This is currently a fairly simple and easy to extend python script that contains all the logic for testing passwords.
* A password plugin client - There is work in the pipe for a Windows Password Filter DLL, a Kerberos module, and a PAM module.  This should satisfy most modern enterprise extensible password management solutions.  If you find this doesn't support you, than feel free to code and request a pull into the main project.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
