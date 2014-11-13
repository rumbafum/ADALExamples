using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace ADALClient.Wcf
{
    public class ADALWcfServiceAuthorizer : IServiceAuthorizer
    {
        private AuthenticationContext _authenticationContext;
        private static string _aadInstance = ConfigurationManager.AppSettings["ida:AADInstance"];
        private static string _tenant = ConfigurationManager.AppSettings["ida:Tenant"];
        private static string _clientId = ConfigurationManager.AppSettings["ida:ClientId"];
        Uri _redirectUri = new Uri(ConfigurationManager.AppSettings["ida:RedirectUri"]);

        private static string _authority = String.Format(CultureInfo.InvariantCulture, _aadInstance, _tenant);

        //
        // To authenticate to the To Do list service, the client needs to know the service's App ID URI.
        // To contact the To Do list service we need it's URL as well.
        //
        private static string _serverResourceId = ConfigurationManager.AppSettings["ADALWcfServerResourceId"];
        private static string _serverBaseAddress = ConfigurationManager.AppSettings["ADALWcfServerBaseAddress"];

        private HttpClient _httpClient = new HttpClient();

        private void Init()
        {
            try
            {
                _authenticationContext = new AuthenticationContext(_authority);
            }
            catch (Exception e)
            {
                MessageBox.Show("Error: ", e.Message);
                return;
            }
        }

        public ADALWcfServiceAuthorizer()
        {
            Init();    
        }

        public string GetAuthorizationHeader()
        {
            AuthenticationResult result = null;
            try
            {
                result = _authenticationContext.AcquireTokenSilent(_serverResourceId, _clientId);
                return result.CreateAuthorizationHeader();
            }
            catch (AdalException ex)
            {
                if (ex.ErrorCode == "failed_to_acquire_token_silently")
                {
                    MessageBox.Show("User needs to login!", "Error", MessageBoxButtons.OK);
                    return null;
                }
                else
                {
                    MessageBox.Show("Message: " + ex.Message + Environment.NewLine + "Inner Exception : " + ex.InnerException.Message, "Error", MessageBoxButtons.OK);
                    return null;
                }
            }
        }

        public void Login(string userName, string password)
        {
            AuthenticationResult result = null;
            try
            {
                result = _authenticationContext.AcquireTokenSilent(_serverResourceId, _clientId);
            }
            catch (AdalException ex)
            {
                if (ex.ErrorCode == "failed_to_acquire_token_silently")
                {
                    UserCredential uc = new UserCredential(userName, password);
                    try
                    {
                        result = _authenticationContext.AcquireToken(_serverResourceId, _clientId, uc);
                    }
                    catch (Exception ee)
                    {
                        MessageBox.Show("Message: " + ee.Message + Environment.NewLine + "Inner Exception : " + ee.InnerException.Message, "Error", MessageBoxButtons.OK);
                        return;
                    }
                }
                else
                {
                    MessageBox.Show("Message: " + ex.Message + Environment.NewLine + "Inner Exception : " + ex.InnerException.Message, "Error", MessageBoxButtons.OK);
                    return;
                }
            }
        }
    }
}
