using ADALClient.ADALWcfServiceReference;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Text;
using System.Threading.Tasks;

namespace ADALClient.Wcf
{
    public class AuthorizedADALWcfServiceClient : Service1Client, IDisposable
    {
        private OperationContextScope _scope;
        private IServiceAuthorizer _serviceAuthorizer;
        private bool _gotChannel;
        private IService1 _service;

        public AuthorizedADALWcfServiceClient(string serviceUrl, IServiceAuthorizer serviceAuthorizer)
            : base("BasicHttpBinding_IService1", serviceUrl)
        {
            this._serviceAuthorizer = serviceAuthorizer;
        }

        protected override IService1 CreateChannel()
        {
            // This part is a little hacky. In summary, we need to create the OperationContextScope so we can add our authorization
            // header. Unfortunately, since we're in a PCL, our extensibility options are very limited. However, we can sneak in
            // while the channel is being created to add the scope and set the header. The challenge is that the call to InnerChannel
            // re-enters this method, so we need to avoid the stack overflow. At the same time, all calls to this method need to 
            // return the same result for this instance for it all to work properly.
            if (!this._gotChannel)
            {
                this._gotChannel = true;

                this._scope = new OperationContextScope(this.InnerChannel);
                HttpRequestMessageProperty hrmp = new HttpRequestMessageProperty();
                hrmp.Headers[HttpRequestHeader.Authorization] = this._serviceAuthorizer.GetAuthorizationHeader();
                OperationContext.Current.OutgoingMessageProperties[HttpRequestMessageProperty.Name] = hrmp;
            }
            else
            {
                this._service = base.CreateChannel();
            }

            return this._service as IService1;
        }

        public void Dispose()
        {
            if (this._scope != null)
            {
                this._scope.Dispose();
                this._scope = null;
            }
        }
    }
}
