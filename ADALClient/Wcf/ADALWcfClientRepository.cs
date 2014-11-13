using ADALClient.ADALWcfServiceReference;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ADALClient.Wcf
{
    public class ADALWcfClientRepository
    {
        private readonly string _serviceUrl;

        private IServiceAuthorizer _serviceAuthorizer;

        private ADALWcfClientRepository() { }
        // Replace the c'tor with this code
        public ADALWcfClientRepository(string serviceUrl, IServiceAuthorizer serviceAuthorizer)
        {
            _serviceUrl = serviceUrl;
            _serviceAuthorizer = serviceAuthorizer;
        }
        
        private ADALWcfServiceReference.Service1Client CreateServiceClient()
        {
              return new AuthorizedADALWcfServiceClient(this._serviceUrl, this._serviceAuthorizer);
        }

        public string GetData(int i)
        {
            ADALWcfServiceReference.Service1Client client = CreateServiceClient();
            return client.GetData(i);
        }

        public CompositeType GetCompositeType()
        {
            CompositeType t = new CompositeType();
            t.BoolValue = true;
            t.StringValue = "BLA";
            ADALWcfServiceReference.Service1Client client = CreateServiceClient();
            return client.GetDataUsingDataContract(t);
        }
    }
}
