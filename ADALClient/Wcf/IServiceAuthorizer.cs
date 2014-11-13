using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ADALClient.Wcf
{
    public interface IServiceAuthorizer
    {
        string GetAuthorizationHeader();
        void Login(string userName, string password);
    }
}
