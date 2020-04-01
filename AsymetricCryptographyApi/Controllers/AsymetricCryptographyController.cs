using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;

namespace AsymetricCryptographyApi.Controllers
{
    [RoutePrefix("key")]
    public class AsymetricCryptographyController : ApiController
    {
        [Route("generate/{mode}")]
        [HttpGet]
        public IHttpActionResult Generate([FromUri] int mode)
        {
            return Ok("test");

        }
    }
}
