using System.Collections.Generic;
using System.Collections.Immutable;
using System.Composition;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CodeActions;
using Microsoft.CodeAnalysis.CodeFixes;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SecurityCodeScan.Analyzers;
using SecurityCodeScan.Analyzers.Utils;
using SF = Microsoft.CodeAnalysis.CSharp.SyntaxFactory;

namespace SecurityCodeScan
{
    [ExportCodeFixProvider(LanguageNames.CSharp, Name = nameof(InsecureCookieCodeFixProvider)), Shared]
    public class InsecureCookieCodeFixProvider : CodeFixProvider
    {
        private const string SecureTitle   = "Add cookie flag Secure";
        private const string HttpOnlyTitle = "Add cookie flag HttpOnly";

        public sealed override ImmutableArray<string> FixableDiagnosticIds =>
            ImmutableArray.Create(InsecureCookieAnalyzer.DiagnosticIdSecure,
                                  InsecureCookieAnalyzer.DiagnosticIdHttpOnly);

        public sealed override FixAllProvider GetFixAllProvider()
        {
            return WellKnownFixAllProviders.BatchFixer;
        }

        public sealed override Task RegisterCodeFixesAsync(CodeFixContext context)
        {
            // TODO: Replace the following code with your own analysis, generating a CodeAction for each fix to suggest
            var diagnostic = context.Diagnostics.First();

            switch (diagnostic.Id)
            {
                //Secure
                case InsecureCookieAnalyzer.DiagnosticIdSecure:
                    context.RegisterCodeFix(
                        CodeAction.Create(
                            title: SecureTitle,
                            createChangedDocument: c => AddSecureFlags(context.Document,
                                                                       diagnostic,
                                                                       c,
                                                                       new[] { "Secure" }),
                            equivalenceKey: SecureTitle),
                        diagnostic);

                    break;

                //HttpOnly
                case InsecureCookieAnalyzer.DiagnosticIdHttpOnly:
                    context.RegisterCodeFix(
                        CodeAction.Create(
                            title: HttpOnlyTitle,
                            createChangedDocument: c => AddSecureFlags(context.Document,
                                                                       diagnostic,
                                                                       c,
                                                                       new[] { "HttpOnly" }),
                            equivalenceKey: HttpOnlyTitle),
                        diagnostic);

                    break;
            }

            return Task.FromResult(0);
        }

        private async Task<Document> AddSecureFlags(Document          document,
                                                    Diagnostic        diagnostic,
                                                    CancellationToken cancellationToken,
                                                    string[]          propertyNames)
        {
            var root               = await document.GetSyntaxRootAsync(cancellationToken).ConfigureAwait(false);
            var variableDeclarator = FindParentNode(root.FindToken(diagnostic.Location.SourceSpan.Start).Parent);

            if (variableDeclarator == null)
                return document; //Abort!

            var variableDeclaration = variableDeclarator.Parent as VariableDeclarationSyntax;
            if (variableDeclaration == null)
                return document; //Abort!

            var parentDeclaration   = variableDeclaration.Parent as LocalDeclarationStatementSyntax;
            if (parentDeclaration == null)
                return document; //Abort!

            var identifierCookie = variableDeclaration.Variables[0];

            //Building the nodes model

            var nodes = new List<SyntaxNode>();
            foreach (var property in propertyNames)
            {
                var newAssignment = SF.ExpressionStatement(
                                          SF.AssignmentExpression(SyntaxKind.SimpleAssignmentExpression,
                                                                  SF.MemberAccessExpression(
                                                                      SyntaxKind.SimpleMemberAccessExpression,
                                                                      SF.IdentifierName(identifierCookie.Identifier),
                                                                      SF.IdentifierName(property)),
                                                                  SF.LiteralExpression(SyntaxKind.TrueLiteralExpression)
                                          ))
                                      .WithLeadingTrivia(CodeFixUtil.KeepLastLine(parentDeclaration.GetLeadingTrivia()));

                /*
                .WithLeadingTrivia(parentDeclaration.GetLeadingTrivia()
                    .Insert(0, SF.ElasticEndOfLine(Environment.NewLine))
                );*/
                nodes.Add(newAssignment);
            }

            //Inserting the nodes
            var newRoot = root.InsertNodesAfter(parentDeclaration, nodes);
            return document.WithSyntaxRoot(newRoot);
        }

        private static VariableDeclaratorSyntax FindParentNode(SyntaxNode node)
        {
            while (node != null)
            {
                var syntax = node as VariableDeclaratorSyntax;
                if (syntax != null)
                {
                    return syntax;
                }

                node = node.Parent;
            }

            return null;
        }
    }
}
