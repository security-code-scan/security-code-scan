using System;
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
        public AspxAnalyzerTest()
        {
            Initialize(new HtmlValidateRequestAnalyzer());
        }

        [TestCategory("Detect")]
        [DataRow("<%@page validateRequest=\"false\"")]
        [DataRow("<%  @page validateRequest=\"false\"")]
        [DataRow("<% @   page validateRequest=\"false\"")]
        [DataRow("<% @   page validateRequest  =\"false\"")]
        [DataRow("<% @   page validateRequest  =  \"false\"")]
        [DataRow("<%@page VAlidateRequest=\"  FAlse  \"")]
        [DataTestMethod]
        public async Task HtmlValidateRequestVulnerable(string element)
        {
            var html = $@"
{element} Title=""About"" Language=""C#"" %>

<asp:Content ID=""BodyContent"" ContentPlaceHolderID=""MainContent"" runat=""server"">
    <h2><%: Title %>.</h2>
    <h3>Your application description page.</h3>
    <p>Use this area to provide additional information.</p>
</asp:Content>
  ";

            var path     = Guid.NewGuid().ToString();
            var expected = new
            {
                Id      = WebConfigAnalyzer.RuleValidateRequest.Id,
                Message = String.Format(WebConfigAnalyzer.RuleValidateRequest.MessageFormat.ToString(),
                                        path,
                                        2,
                                        element)
            };

            var diagnostics = await Analyze(html, path).ConfigureAwait(false);
            diagnostics.Verify(call => call(It.Is<Diagnostic>(d => d.Id                  == expected.Id
                                                                   && d.GetMessage(null) == expected.Message)), Times.Once);
        }

        [TestCategory("Safe")]
        [DataRow("<%@page validateRequest=\"true\"")]
        [DataRow("<%@page VAlidateRequest=\"  TRue  \"")]
        [TestMethod]
        public async Task HtmlValidateRequestSafe(string element)
        {
            var html = $@"
{element} Title=""About"" Language=""C#"" %>

<asp:Content ID=""BodyContent"" ContentPlaceHolderID=""MainContent"" runat=""server"">
    <h2><%: Title %>.</h2>
    <h3>Your application description page.</h3>
    <p>Use this area to provide additional information.</p>
</asp:Content>
  ";

            var diagnostics = await Analyze(html, Guid.NewGuid().ToString()).ConfigureAwait(false);
            diagnostics.Verify(call => call(It.Is<Diagnostic>(d => d.Id == WebConfigAnalyzer.RuleValidateRequest.Id)), Times.Never);
        }
    }
}
