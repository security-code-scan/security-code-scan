using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using SecurityCodeScan.Analyzers;

namespace SecurityCodeScan.Test
{
    [TestClass]
    public class AspxAnalyzerTest : ExternalFileAnalyzerTest
    {
        public AspxAnalyzerTest() : base(new HtmlValidateRequestAnalyzer()) { }

        [DataRow("<%@page validateRequest=\"false\"")]
        [DataRow("<%  @page validateRequest=\"false\"")]
        [DataRow("<% @   page validateRequest=\"false\"")]
        [DataRow("<% @   page validateRequest  =\"false\"")]
        [DataRow("<% @   page validateRequest  =  \"false\"")]
        [DataRow("<%@page VAlidateRequest=\"  FAlse  \"")]
        [DataTestMethod]
        public async Task HtmlValidateRequestVulnerable(string element)
        {
            string html = $@"
{element} Title=""About"" Language=""C#"" %>

<asp:Content ID=""BodyContent"" ContentPlaceHolderID=""MainContent"" runat=""server"">
    <h2><%: Title %>.</h2>
    <h3>Your application description page.</h3>
    <p>Use this area to provide additional information.</p>
</asp:Content>
              ";

            var path     = Path.GetTempFileName();
            var expected = new
            {
                Id      = WebConfigAnalyzer.RuleValidateRequest.Id,
                Message = String.Format(WebConfigAnalyzer.RuleValidateRequest.MessageFormat.ToString(),
                                        path,
                                        2,
                                        element)
            };

            var diagnostics = await Analyze(html, path);
            diagnostics.Verify(call => call(It.Is<Diagnostic>(d => d.Id                  == expected.Id
                                                                   && d.GetMessage(null) == expected.Message)), Times.Once);
        }

        [DataRow("<%@page validateRequest=\"true\"")]
        [DataRow("<%@page VAlidateRequest=\"  TRue  \"")]
        [TestMethod]
        public async Task HtmlValidateRequestSafe(string element)
        {
            string html = $@"
{element} Title=""About"" Language=""C#"" %>

<asp:Content ID=""BodyContent"" ContentPlaceHolderID=""MainContent"" runat=""server"">
    <h2><%: Title %>.</h2>
    <h3>Your application description page.</h3>
    <p>Use this area to provide additional information.</p>
</asp:Content>
              ";

            var diagnostics = await Analyze(html, Path.GetTempFileName());
            diagnostics.Verify(call => call(It.Is<Diagnostic>(d => d.Id == WebConfigAnalyzer.RuleValidateRequest.Id)), Times.Never);
        }
    }
}
