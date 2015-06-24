# googlapps-sso
Sample app for SSO between google apps domains.

This demonstrates SAML SSO with google properties and is is intended for *testing/POC only*
The script basically runs a SAML IDP within a docker container.

To use:
1. Create public/private keypair
    remember to set the CN= to your domain
    the certificates provided in github is set for sso.yourdomain.com
2. Login to your google apps admin console (admin.google.com/a/yourdomain.com)
    Navigate to https://admin.google.com/AdminHome?fral=1#SecuritySettings:flyout=sso
    set following config:
      Login:  https://sso.yourdomain.com:28080/login
      Logout: https://sso.yourdomain.com:28080/logout
      Change Password: https://sso.yourdomain.com:28080/passwd
      upload the public cert (ssl.crt)
3. If you are running the docker container locally,
      On your laptop edit
         /etc/hosts
            127.0.0.1 localhost sso.yourdomain.com
4. Install docker.io
5. make a folder called sso and copy all the files from the github repo into it.
6. Create the docker container
          docker build -t sso .
7. Run the container
          docker run -t -p 28080:28080 sso --debug  --use_ssl --cert_file=ssl.crt --key_file=ssl.key --key_blank_pwd
8. At this point, the IDP is running locally on port sso.yourdomain.com:28080
9. If you attempt a new login to https://mail.google.com/a/yourdomain.com, you will get redirected to a login screen on your IDP
10. The IDP will authenticate **ANY** user in your apps domain so if you have a user called user1@yourdomain.com, enter in 'user1', any password
      and yourdomain.com in the IDP login screen
11. If successful, you will get redirected to the SAML POST binding screen so  you can see the actual XML signed POST text.
12. Click contineu and if the sigatures and validUntil= parameters are ok, you will be logged in as user1


If you want to generate your own keypairs:
openssl req -x509 -newkey rsa:2048 -keyout ssl.key -out ssl.crt -days 365 -nodes
