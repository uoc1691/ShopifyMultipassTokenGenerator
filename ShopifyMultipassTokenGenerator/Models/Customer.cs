using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace ShopifyMultipassTokenGenerator.Models
{
    /// <summary>
    /// Base class that holds customer data. If you want to include more details about the customer, create a new class and inherit this class.
    /// </summary>
    public class Customer
    {
        [JsonProperty(propertyName: "email")]
        public string Email { get; set; }

        //2013-04-11T15:16:23-04:00
        [JsonProperty(propertyName: "created_at")]
        public string CreatedAt { get; set; }


        public Customer()
        {
            this.CreatedAt = DateTime.Now.ToString("yyyy-MM-ddTHH\\:mm\\:sszzz");
        }
    }
}
