using ADALClient.Wcf;
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
    public partial class Form2 : Form
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
        private static string serverResourceId = ConfigurationManager.AppSettings["ADALWcfServerResourceId"];
        private static string serverBaseAddress = ConfigurationManager.AppSettings["ADALWcfServerBaseAddress"];

        ADALWcfClientRepository _client;
        IServiceAuthorizer _service;

        public Form2()
        {
            InitializeComponent();
            logoutButton.Visible = false;
            getDataButton.Enabled = false;

            string url = "http://localhost/ADALWcf/Service1.svc";
            _service = new ADALWcfServiceAuthorizer();
            _client = new ADALWcfClientRepository(url, _service);
        }

        private void loginButton_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrEmpty(userTextBox.Text) || string.IsNullOrEmpty(passwordTextBox.Text))
            {
                MessageBox.Show("Fill your login info", "Invalid Login Data", MessageBoxButtons.OK);
                return;
            }

            _service.Login(userTextBox.Text, passwordTextBox.Text);
            getDataButton.Enabled = true;
            loginButton.Enabled = false;
            userTextBox.ReadOnly = true;
            passwordTextBox.ReadOnly = true;
            logoutButton.Visible = true;
        }

        private void getDataButton_Click(object sender, EventArgs e)
        {
            GetData();
        }

        private void logoutButton_Click(object sender, EventArgs e)
        {
            getDataButton.Enabled = false;
            loginButton.Enabled = true;
            userTextBox.ReadOnly = false;
            passwordTextBox.ReadOnly = false;
            logoutButton.Visible = false;
        }

        private void GetData()
        {
            MessageBox.Show(_client.GetData(Convert.ToInt16(dataTextBox.Text)));
        }

    }
}
