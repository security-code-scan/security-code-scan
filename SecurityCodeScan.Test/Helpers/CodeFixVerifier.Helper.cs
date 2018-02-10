using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CodeActions;
using Microsoft.CodeAnalysis.Formatting;
using Microsoft.CodeAnalysis.Simplification;

namespace SecurityCodeScan.Test.Helpers
{
    /// <summary>
    /// Diagnostic Producer class with extra methods dealing with applying codefixes
    /// All methods are static
    /// </summary>
    public abstract partial class CodeFixVerifier : DiagnosticVerifier
    {
        /// <summary>
        /// Apply the inputted CodeAction to the inputted document.
        /// Meant to be used to apply codefixes.
        /// </summary>
        /// <param name="document">The Document to apply the fix on</param>
        /// <param name="codeAction">A CodeAction that will be applied to the Document.</param>
        /// <returns>A Document with the changes from the CodeAction</returns>
        private static async Task<Document> ApplyFix(Document document, CodeAction codeAction, CancellationToken cancellationToken)
        {
            try
            {
                var operations = await codeAction.GetOperationsAsync(cancellationToken).ConfigureAwait(false);
                var solution   = operations.OfType<ApplyChangesOperation>().Single().ChangedSolution;
                return solution.GetDocument(document.Id);
            }
            catch (AggregateException e)
            {
                if (e.InnerExceptions.Count <= 0)
                    throw;

                foreach (var ex in e.InnerExceptions)
                {
                    Console.WriteLine("Exception thrown during code fix: " + ex.Message);
                    Console.WriteLine(ex.StackTrace);
                }

                throw;
            }
        }

        /// <summary>
        /// Compare two collections of Diagnostics and returns a list of any new diagnostics that
        /// appear only in the second collection.
        /// Note: Considers Diagnostics to be the same if they have the same Ids.
        /// In the case of multiple diagnostics with the same Id in a row,
        /// this method may not necessarily return the new one.
        /// </summary>
        /// <param name="diagnostics">The Diagnostics that existed in the code before the CodeFix was applied</param>
        /// <param name="newDiagnostics">The Diagnostics that exist in the code after the CodeFix was applied</param>
        /// <returns>A list of Diagnostics that only surfaced in the code after the CodeFix was applied</returns>
        private static IEnumerable<Diagnostic> GetNewDiagnostics(IEnumerable<Diagnostic> diagnostics,
                                                                 IEnumerable<Diagnostic> newDiagnostics)
        {
            var oldArray = diagnostics.OrderBy(d => d.Location.SourceSpan.Start).ToArray();
            var newArray = newDiagnostics.OrderBy(d => d.Location.SourceSpan.Start).ToArray();

            int oldIndex = 0;
            int newIndex = 0;

            while (newIndex < newArray.Length)
            {
                if (oldIndex < oldArray.Length && oldArray[oldIndex].Id == newArray[newIndex].Id)
                {
                    ++oldIndex;
                    ++newIndex;
                }
                else
                {
                    yield return newArray[newIndex++];
                }
            }
        }

        /// <summary>
        /// Get the existing compiler diagnostics on the inputted document.
        /// </summary>
        /// <param name="document">The Document to run the compiler diagnostic analyzers on</param>
        /// <returns>The compiler diagnostics that were found in the code</returns>
        private static async Task<ImmutableArray<Diagnostic>> GetCompilerDiagnostics(Document document, CancellationToken cancellationToken)
        {
            return (await document.GetSemanticModelAsync(cancellationToken).ConfigureAwait(false)).GetDiagnostics();
        }

        /// <summary>
        /// Given a document, turn it into a string based on the syntax root
        /// </summary>
        /// <param name="document">The Document to be converted to a string</param>
        /// <returns>A string containing the syntax of the Document after formatting</returns>
        private static async Task<string> GetStringFromDocument(Document document, CancellationToken cancellationToken)
        {
            var simplifiedDoc = await Simplifier.ReduceAsync(document,
                                                             Simplifier.Annotation,
                                                             cancellationToken: cancellationToken)
                                                .ConfigureAwait(false);
            var root          = await simplifiedDoc.GetSyntaxRootAsync(cancellationToken).ConfigureAwait(false);
            root              = Formatter.Format(root, Formatter.Annotation, simplifiedDoc.Project.Solution.Workspace);
            return root.GetText().ToString();
        }
    }
}
