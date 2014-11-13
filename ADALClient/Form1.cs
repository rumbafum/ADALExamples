using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Configuration;
using System.Data;
using System.Drawing;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace ADALClient
{
    public partial class Form1 : Form
    {
        private static string aadInstance = ConfigurationManager.AppSettings["ida:AADInstance"];
        private static string tenant = ConfigurationManager.AppSettings["ida:Tenant"];
        private static string clientId = ConfigurationManager.AppSettings["ida:ClientId"];
        Uri redirectUri = new Uri(ConfigurationManager.AppSettings["ida:RedirectUri"]);

        private static string authority = String.Format(CultureInfo.InvariantCulture, aadInstance, tenant);

        //
        // To authenticate to the To Do list service, the client needs to know the service's App ID URI.
        // To contact the To Do list service we need it's URL as well.
        //
        private static string serverResourceId = ConfigurationManager.AppSettings["ADALServerResourceId"];
        private static string serverBaseAddress = ConfigurationManager.AppSettings["ADALServerBaseAddress"];

        private HttpClient httpClient = new HttpClient();
        private AuthenticationContext authContext = null;

        public Form1()
        {
            InitializeComponent();
            logoutButton.Visible = false;
            getDataButton.Enabled = false;

            authContext = new AuthenticationContext(authority);
        }

        private void loginButton_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrEmpty(userTextBox.Text) || string.IsNullOrEmpty(passwordTextBox.Text))
            {
                MessageBox.Show("Fill your login info", "Invalid Login Data", MessageBoxButtons.OK);
                return;
            }

            AuthenticationResult result = null;
            try
            {
                result = authContext.AcquireTokenSilent(serverResourceId, clientId);
            }
            catch (AdalException ex) 
            {
                if (ex.ErrorCode == "failed_to_acquire_token_silently")
                {
                    UserCredential uc = new UserCredential(userTextBox.Text, passwordTextBox.Text);
                    try
                    {
                        result = authContext.AcquireToken(serverResourceId, clientId, uc);
                        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", result.AccessToken);
                        getDataButton.Enabled = true;
                        loginButton.Enabled = false;
                        userTextBox.ReadOnly = true;
                        passwordTextBox.ReadOnly = true;
                        logoutButton.Visible = true;
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

        private void getDataButton_Click(object sender, EventArgs e)
        {
            AuthenticationResult result = null;
            try
            {
                result = authContext.AcquireToken(serverResourceId, clientId, redirectUri, PromptBehavior.Never);
            }
            catch (AdalException ex)
            {
                // There is no access token in the cache, so prompt the user to sign-in.
                if (ex.ErrorCode == "user_interaction_required")
                {
                    MessageBox.Show("Please sign in first");
                }
                else
                {
                    // An unexpected error occurred.
                    string message = ex.Message;
                    if (ex.InnerException != null)
                    {
                        message += "Inner Exception : " + ex.InnerException.Message;
                    }
                    MessageBox.Show(message);
                }

                return;
            }
            GetData();
        }

        private void logoutButton_Click(object sender, EventArgs e)
        {
            httpClient = new HttpClient();
            getDataButton.Enabled = false;
            loginButton.Enabled = true;
            userTextBox.ReadOnly = false;
            passwordTextBox.ReadOnly = false;
            logoutButton.Visible = false;
        }

        private async void GetData()
        {
            AuthenticationResult result = null;
            try
            {
                result = authContext.AcquireToken(serverResourceId, clientId, redirectUri, PromptBehavior.Never);
            }
            catch (AdalException ex)
            {
                // There is no access token in the cache, so prompt the user to sign-in.
                if (ex.ErrorCode == "user_interaction_required")
                {
                    MessageBox.Show("Please sign in first");
                }
                else
                {
                    // An unexpected error occurred.
                    string message = ex.Message;
                    if (ex.InnerException != null)
                    {
                        message += "Inner Exception : " + ex.InnerException.Message;
                    }
                    MessageBox.Show(message);
                }

                return;
            }
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", result.AccessToken);
            HttpResponseMessage response = await httpClient.GetAsync(serverBaseAddress + "/api/Data/" + dataTextBox.Text);
            if (response.IsSuccessStatusCode)
            {
                // Read the response and databind to the GridView to display To Do items.
                string s = await response.Content.ReadAsStringAsync();
                MessageBox.Show("Result: " + s);
            }
            else
            {
                MessageBox.Show("An error occurred : " + response.ReasonPhrase);
            }
        }

    }
}
