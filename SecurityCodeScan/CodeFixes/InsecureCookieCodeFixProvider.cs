using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CodeActions;
using Microsoft.CodeAnalysis.CodeFixes;
using SF = Microsoft.CodeAnalysis.CSharp.SyntaxFactory;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SecurityCodeScan.Analyzers;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Composition;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using SecurityCodeScan.Analyzers.Utils;

namespace SecurityCodeScan
{
    [ExportCodeFixProvider(LanguageNames.CSharp, Name = nameof(InsecureCookieCodeFixProvider)), Shared]
    public class InsecureCookieCodeFixProvider : CodeFixProvider
    {
        private const string SecureTitle = "Add cookie flag Secure";
        private const string HttpOnlyTitle = "Add cookie flag HttpOnly";

        public sealed override ImmutableArray<string> FixableDiagnosticIds => 
            ImmutableArray.Create(InsecureCookieAnalyzer.DiagnosticIdSecure, InsecureCookieAnalyzer.DiagnosticIdHttpOnly);

        public sealed override FixAllProvider GetFixAllProvider()
        {
            return WellKnownFixAllProviders.BatchFixer;
        }

        public sealed override async Task RegisterCodeFixesAsync(CodeFixContext context)
        {
            var root = await context.Document.GetSyntaxRootAsync(context.CancellationToken).ConfigureAwait(false);

            // TODO: Replace the following code with your own analysis, generating a CodeAction for each fix to suggest
            var diagnostic = context.Diagnostics.First();
            
            switch(diagnostic.Id) {
                //Secure
                case InsecureCookieAnalyzer.DiagnosticIdSecure:
                    context.RegisterCodeFix(
                        CodeAction.Create(
                            title: SecureTitle,
                            createChangedDocument: c => AddSecureFlags(context.Document, diagnostic, c, new string[] { "Secure" }),
                            equivalenceKey: SecureTitle),
                        diagnostic);

                    break;
                //HttpOnly
                case InsecureCookieAnalyzer.DiagnosticIdHttpOnly:
                    context.RegisterCodeFix(
                        CodeAction.Create(
                            title: HttpOnlyTitle,
                            createChangedDocument: c => AddSecureFlags(context.Document, diagnostic, c, new string[] { "HttpOnly" }),
                            equivalenceKey: HttpOnlyTitle),
                        diagnostic);
                    break;
            }
            
        }

        private async Task<Document> AddSecureFlags(Document document, Diagnostic diagnostic, CancellationToken cancellationToken, string[] propertyNames)
        {
            var root = await document.GetSyntaxRootAsync(cancellationToken).ConfigureAwait(false);
            var variableDeclarator = FindParentNode(root.FindToken(diagnostic.Location.SourceSpan.Start).Parent);

            if (variableDeclarator == null) return document; //Abort!

            VariableDeclarationSyntax variableDeclaration = variableDeclarator.Parent as VariableDeclarationSyntax;
            LocalDeclarationStatementSyntax parentDeclaration = variableDeclaration.Parent as LocalDeclarationStatementSyntax;

            if (variableDeclaration == null || parentDeclaration == null) return document; //Abort!
            
            var identifierCookie = variableDeclaration.Variables[0];

            //Building the nodes model

            var nodes = new List<SyntaxNode>();
            foreach (var property in propertyNames) {
                var newAssignment = SF.ExpressionStatement(
                    SF.AssignmentExpression(SyntaxKind.SimpleAssignmentExpression,
                    SF.MemberAccessExpression(
                        SyntaxKind.SimpleMemberAccessExpression,
                        SF.IdentifierName(identifierCookie.Identifier),
                        SF.IdentifierName(property))
                    ,
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

        private VariableDeclaratorSyntax FindParentNode(SyntaxNode node) {
            if (node == null) {
                return null;
            }
            if (node is VariableDeclaratorSyntax) {
                return node as VariableDeclaratorSyntax;
            }
            return FindParentNode(node.Parent);
        }
    }
}
