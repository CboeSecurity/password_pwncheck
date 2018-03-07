# password_pwncheck
Enterprise Password Quality Checking using any hash data sources (HaveIBeenPwned lists, et al)

The purpose of this project is to help companies maintain a stronger password policy without having to jump through too many hoops.  Currently, we support NIST 800-63B features such as testing the password against a long minimum length (default of 15), not matching prev
ious passwords (or similar entries), and most important- the password can't belong to a breach list.

The project consists of two parts:

* A password server -  This is currently a fairly simple and easy to extend python script that contains all the logic for testing passwords.
* A password plugin client - There is work in the pipe for a Windows Password Filter DLL, a Kerberos module, and a PAM module.  This should satisfy most modern enterprise extensible password management solutions.  If you find this doesn't support you, than feel free to code and request a pull into the main project.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# Installation

> This code is very fresh- it is functional and has been tested to work, but the installation and configuration will require some level of knowledge of configuring variable values in scripts and know-how on how Kerberos/PAM/AD perform password change management.  This is mainly because I make no claims that I am a technical writer, so I may be covering configuration in broad strokes...

(Under Construction)

## Password Server
* The password server needs to have downloaded password hash lists provided to it.  These should sit in the `./db` folder.  A great place to start for your breached passwords is [https://haveibeenpwned.com/Passwords], Thanks to Troy Hunt for all his efforts (he is in large part the inspiration behind this project).
* Also, make sure you have a valid key/certificate chain.  These two files should have their paths matched with the `SSLCertFile` and `SSLKeyFile` variables.
* The code is written in python 2.7.  You should be able to run it via `python-2.7 ./pwned-password-server.py`

## AD Password filter DLL
* From a Dev Studio command line, run `resbuilder.bat` from its directory in the ad-password-pwncheck project
* Build the solution, specifically the `ad_password_pwncheck` project.
* Copy the resulting ad_password_pwncheck.dll into the `%windir%\system32` folder on all domain controllers in the domain.
* Run `wevtutil im Resources.man /rf:"%windir%\system32\ad_password_pwncheck.dll" /mf:"%windir%\system32\ad_password_pwncheck.dll"` to properly register windows event logs
* Run the included registry file to enable registry settings

## Kerberos filter DLL

* Run the `./build.sh` too, make sure openssl-devel and curl-devel modules are loaded in your SLES/RedHat/Debian derived distribution.
* Copy the `/lib/security/krb_password_pwncheck.so` library to the kerberos plugins/pwqual folder.
* Configure the krb5.conf to have the correct path:
```
[plugins]
    pwqual = {
      module = pwncheck:pwqual/krb_password_pwncheck.so 
    }
````
