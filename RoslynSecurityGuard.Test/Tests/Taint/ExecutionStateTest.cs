using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RoslynSecurityGuard.Analyzers.Taint;

namespace RoslynSecurityGuard.Tests
{
    [TestClass]
    public class ExecutionStateTest
    {
        [TestMethod]
        public void GetValueByIdentifierTest()
        {
            var ctx = new SyntaxNodeAnalysisContext();
            var executionState = new ExecutionState(ctx);

            var variableState = executionState.GetValueByIdentifier("none");
            Assert.IsNotNull(variableState.tags);
            Assert.AreEqual(VariableTaint.UNKNOWN, variableState.taint);
        }
    }
}
