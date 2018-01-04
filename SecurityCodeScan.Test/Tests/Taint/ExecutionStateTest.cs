using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers.Taint;

namespace SecurityCodeScan.Tests
{
    [TestClass]
    public class ExecutionStateTest
    {
        [TestMethod]
        public void GetValueByIdentifierTest()
        {
            var ctx            = new SyntaxNodeAnalysisContext();
            var executionState = new ExecutionState(ctx);

            var variableState = executionState.GetValueByIdentifier("none");
            Assert.IsNotNull(variableState.Tags);
            Assert.AreEqual(VariableTaint.Unknown, variableState.Taint);
        }
    }
}
