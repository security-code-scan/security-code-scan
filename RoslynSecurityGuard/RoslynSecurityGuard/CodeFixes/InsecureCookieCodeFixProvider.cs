using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CodeActions;
using Microsoft.CodeAnalysis.CodeFixes;
using SF = Microsoft.CodeAnalysis.CSharp.SyntaxFactory;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using RoslynSecurityGuard.Analyzers;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Composition;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace RoslynSecurityGuard
{
    [ExportCodeFixProvider(LanguageNames.CSharp, Name = nameof(InsecureCookieCodeFixProvider)), Shared]
    public class InsecureCookieCodeFixProvider : CodeFixProvider
    {
        private const string title = "Add cookie flags Secure and HttpOnly";

        public sealed override ImmutableArray<string> FixableDiagnosticIds
        {
            get
            {
                return ImmutableArray.Create(InsecureCookieAnalyzer.DiagnosticIdHttpOnly,
              InsecureCookieAnalyzer.DiagnosticIdSecure);
            }
        }

        public sealed override FixAllProvider GetFixAllProvider()
        {
            return WellKnownFixAllProviders.BatchFixer;
        }

        public sealed override async Task RegisterCodeFixesAsync(CodeFixContext context)
        {
            var root = await context.Document.GetSyntaxRootAsync(context.CancellationToken).ConfigureAwait(false);

            // TODO: Replace the following code with your own analysis, generating a CodeAction for each fix to suggest
            var diagnostic = context.Diagnostics.First();

            context.RegisterCodeFix(
                CodeAction.Create(
                    title: title,
                    createChangedDocument: c => AddSecureFlags(context.Document, diagnostic, c),
                    equivalenceKey: title),
                diagnostic);
        }

        private async Task<Document> AddSecureFlags(Document document, Diagnostic diagnostic, CancellationToken cancellationToken)
        {
            var root = await document.GetSyntaxRootAsync(cancellationToken).ConfigureAwait(false);
            var objectCreation = root.FindToken(diagnostic.Location.SourceSpan.Start).Parent.AncestorsAndSelf().OfType<ObjectCreationExpressionSyntax>().First();

            LocalDeclarationStatementSyntax parentDeclaration = null;
            VariableDeclarationSyntax parentVariable = null;
            SyntaxNode parent = null;
            while((parent = objectCreation.Parent) != null)
            {
                if (parent is LocalDeclarationStatementSyntax) {
                    parentDeclaration = (LocalDeclarationStatementSyntax)parent;
                }
                if (parent is VariableDeclarationSyntax)
                {
                    parentVariable = (VariableDeclarationSyntax)parent;
                }
            }


            var identifierCookie = parentVariable.Variables[0];


            if (parentDeclaration != null) {

                var newInvocation = SF.InvocationExpression(
                SF.MemberAccessExpression(
                    SyntaxKind.SimpleMemberAccessExpression,
                    SF.IdentifierName(identifierCookie.Identifier),
                    SF.IdentifierName("Secure")),
                SF.ArgumentList(
                    SF.SingletonSeparatedList(
                        SF.Argument(SF.LiteralExpression(SyntaxKind.TrueLiteralExpression))
                        )
                    )
                );

                var newAssignment = SF.AssignmentExpression(SyntaxKind.SimpleAssignmentExpression,
                    SF.MemberAccessExpression(
                        SyntaxKind.SimpleMemberAccessExpression,
                        SF.IdentifierName(identifierCookie.Identifier),
                        SF.IdentifierName("Secure")
                    )
                    ,
                    SF.LiteralExpression(SyntaxKind.TrueLiteralExpression)
                    );

                root.InsertNodesAfter(parentDeclaration, new List<SyntaxNode> { newAssignment });

                return document.WithSyntaxRoot(root);
            }
            else {
                return document;
            }
        }
    }
}
