#nullable disable
using System.Collections.Generic;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace SecurityCodeScan.Analyzers.Utils
{
    internal sealed class CSharpSyntaxNodeHelper : SyntaxNodeHelper
    {
        public static CSharpSyntaxNodeHelper Default { get; } = new CSharpSyntaxNodeHelper();

        private CSharpSyntaxNodeHelper()
        {
        }

        public override ITypeSymbol GetClassDeclarationTypeSymbol(SyntaxNode node, SemanticModel semanticModel)
        {
            if (node == null)
            {
                return null;
            }

            SyntaxKind kind = node.Kind();
            if (kind == SyntaxKind.ClassDeclaration)
            {
                return semanticModel.GetDeclaredSymbol((ClassDeclarationSyntax)node);
            }

            return null;
        }

        public override SyntaxNode GetAssignmentLeftNode(SyntaxNode node)
        {
            if (node == null)
            {
                return null;
            }

            var kind = node.Kind();
            if (kind == SyntaxKind.VariableDeclarator)
                return (VariableDeclaratorSyntax)node;

            return (node as AssignmentExpressionSyntax)?.Left;
        }

        public override string GetAssignmentLeftNodeName(SyntaxNode node)
        {
            if (node == null)
            {
                return null;
            }

            var kind = node.Kind();
            if (kind == SyntaxKind.VariableDeclarator)
                return ((VariableDeclaratorSyntax)node).Identifier.Text;

            return (node as AssignmentExpressionSyntax)?.Left.ToString();
        }

        public override SyntaxNode GetAssignmentRightNode(SyntaxNode node)
        {
            if (node == null)
            {
                return null;
            }

            SyntaxKind kind = node.Kind();
            switch (kind)
            {
                case SyntaxKind.AddAssignmentExpression:
                case SyntaxKind.SimpleAssignmentExpression:
                    return ((AssignmentExpressionSyntax)node).Right;
                case SyntaxKind.VariableDeclarator:
                    EqualsValueClauseSyntax initializer = ((VariableDeclaratorSyntax)node).Initializer;
                    if (initializer != null)
                    {
                        return initializer.Value;
                    }

                    break;
            }

            return null;
        }

        public override SyntaxNode GetMemberAccessNameNode(SyntaxNode node)
        {
            if (node?.Kind() == SyntaxKind.SimpleMemberAccessExpression)
            {
                return ((MemberAccessExpressionSyntax)node)?.Name;
            }

            return null;
        }

        public override SyntaxNode GetMemberAccessExpressionNode(SyntaxNode node)
        {
            if (node == null)
            {
                return null;
            }

            SyntaxKind kind = node.Kind();
            if (kind == SyntaxKind.SimpleMemberAccessExpression)
            {
                return ((MemberAccessExpressionSyntax)node).Expression;
            }
            else if (kind == SyntaxKind.MemberBindingExpression &&
                     node?.Parent?.Parent.Kind() == SyntaxKind.ConditionalAccessExpression)
            {
                return ((ConditionalAccessExpressionSyntax)node.Parent.Parent).Expression;
            }

            return null;
        }

        public override SyntaxNode GetInvocationExpressionNode(SyntaxNode node)
        {
            if (node == null)
            {
                return null;
            }

            SyntaxKind kind = node.Kind();
            if (kind != SyntaxKind.InvocationExpression)
            {
                return null;
            }

            return ((InvocationExpressionSyntax)node).Expression;
        }

        public override SyntaxNode GetDefaultValueForAnOptionalParameter(SyntaxNode declNode, int paramIndex)
        {
            if (!(declNode is BaseMethodDeclarationSyntax methodDecl))
                return null;

            ParameterListSyntax paramList = methodDecl.ParameterList;
            if (paramIndex >= paramList.Parameters.Count)
                return null;

            EqualsValueClauseSyntax equalsValueNode = paramList.Parameters[paramIndex].Default;
            if (equalsValueNode != null)
            {
                return equalsValueNode.Value;
            }
            return null;
        }

        public override SyntaxNode GetAttributeArgumentExpressionNode(SyntaxNode node)
        {
            if (!(node is AttributeArgumentSyntax argument))
                return null;

            return argument.Expression;
        }

        protected override IEnumerable<SyntaxNode> GetCallArgumentExpressionNodes(SyntaxNode node, CallKind callKind)
        {
            if (node == null)
                return Enumerable.Empty<SyntaxNode>();

            ArgumentListSyntax argList = null;
            SyntaxKind kind = node.Kind();
            switch (kind)
            {
                case SyntaxKind.InvocationExpression when (callKind & CallKind.Invocation) != 0:
                {
                    var invocationNode = (InvocationExpressionSyntax)node;
                    argList = invocationNode.ArgumentList;
                    break;
                }
                case SyntaxKind.ObjectCreationExpression when (callKind & CallKind.ObjectCreation) != 0:
                {
                    var invocationNode = (ObjectCreationExpressionSyntax)node;
                    argList = invocationNode.ArgumentList;
                    break;
                }
            }
            if (argList != null)
            {
                return argList.Arguments.Select(arg => arg.Expression);
            }

            return Enumerable.Empty<SyntaxNode>();
        }

        public override IEnumerable<SyntaxNode> GetObjectInitializerExpressionNodes(SyntaxNode node)
        {
            IEnumerable<SyntaxNode> empty = Enumerable.Empty<SyntaxNode>();
            if (node == null)
            {
                return empty;
            }

            SyntaxKind kind = node.Kind();
            if (kind != SyntaxKind.ObjectCreationExpression)
            {
                return empty;
            }

            var objectCreationNode = (ObjectCreationExpressionSyntax)node;
            if (objectCreationNode.Initializer == null)
            {
                return empty;
            }

            return objectCreationNode.Initializer.Expressions;
        }

        public override bool IsMethodInvocationNode(SyntaxNode node)
        {
            if (node == null)
            {
                return false;
            }
            SyntaxKind kind = node.Kind();
            return kind == SyntaxKind.InvocationExpression || kind == SyntaxKind.ObjectCreationExpression;
        }

        public override bool IsSimpleMemberAccessExpressionNode(SyntaxNode node)
        {
            SyntaxKind? kind = node?.Kind();
            return kind == SyntaxKind.SimpleMemberAccessExpression;
        }

        public override bool IsObjectCreationExpressionNode(SyntaxNode node)
        {
            SyntaxKind? kind = node?.Kind();
            return kind == SyntaxKind.ObjectCreationExpression;
        }

        public override IMethodSymbol GetCalleeMethodSymbol(SyntaxNode node, SemanticModel semanticModel)
        {
            ISymbol symbol = GetReferencedSymbol(node, semanticModel);

            if (symbol != null && symbol.Kind == SymbolKind.Method)
            {
                return (IMethodSymbol)symbol;
            }

            return null;
        }

        public override IMethodSymbol GetCallerMethodSymbol(SyntaxNode node, SemanticModel semanticModel)
        {
            if (node == null)
            {
                return null;
            }

            MethodDeclarationSyntax declaration = node.AncestorsAndSelf().OfType<MethodDeclarationSyntax>().FirstOrDefault();
            if (declaration != null)
            {
                return semanticModel.GetDeclaredSymbol(declaration);
            }

            ConstructorDeclarationSyntax contructor = node.AncestorsAndSelf().OfType<ConstructorDeclarationSyntax>().FirstOrDefault();
            if (contructor != null)
            {
                return semanticModel.GetDeclaredSymbol(contructor);
            }

            return null;
        }

        public override ITypeSymbol GetEnclosingTypeSymbol(SyntaxNode node, SemanticModel semanticModel)
        {
            if (node == null)
            {
                return null;
            }

            ClassDeclarationSyntax declaration = node.AncestorsAndSelf().OfType<ClassDeclarationSyntax>().FirstOrDefault();

            if (declaration == null)
            {
                return null;
            }

            return semanticModel.GetDeclaredSymbol(declaration);
        }

        public override IEnumerable<SyntaxNode> GetDescendantAssignmentExpressionNodes(SyntaxNode node)
        {
            IEnumerable<SyntaxNode> empty = Enumerable.Empty<SyntaxNode>();
            if (node == null)
            {
                return empty;
            }

            return node.DescendantNodesAndSelf().OfType<AssignmentExpressionSyntax>();
        }

        public override IEnumerable<SyntaxNode> GetDescendantMemberAccessExpressionNodes(SyntaxNode node)
        {
            IEnumerable<SyntaxNode> empty = Enumerable.Empty<SyntaxNode>();
            if (node == null)
            {
                return empty;
            }

            return node.DescendantNodesAndSelf().OfType<MemberAccessExpressionSyntax>();
        }

        public override IEnumerable<SyntaxNode> GetDeclarationAttributeNodes(SyntaxNode node)
        {
            var attributeLists = new SyntaxList<AttributeListSyntax>();
            switch (node.Kind())
            {
                case SyntaxKind.PropertyDeclaration:
                    attributeLists = ((PropertyDeclarationSyntax)node).AttributeLists;
                    break;
                case SyntaxKind.MethodDeclaration:
                    attributeLists = ((MethodDeclarationSyntax)node).AttributeLists;
                    break;
                case SyntaxKind.ClassDeclaration:
                    attributeLists = ((ClassDeclarationSyntax)node).AttributeLists;
                    break;
            }

            var result = new List<SyntaxNode>();
            foreach (var attributeList in attributeLists)
            {
                if (attributeList.Attributes.Count == 0)
                    continue;

                result.AddRange(attributeList.Attributes);
            }

            return result;
        }

        public override IEnumerable<SyntaxNode> GetAttributeArgumentNodes(SyntaxNode node)
        {
            if (!(node is AttributeSyntax attribute))
                return Enumerable.Empty<SyntaxNode>();

            return attribute.ArgumentList?.Arguments ?? Enumerable.Empty<SyntaxNode>();
        }

        public override bool IsObjectCreationExpressionUnderFieldDeclaration(SyntaxNode node)
        {
            return node != null &&
                   node.Kind() == SyntaxKind.ObjectCreationExpression &&
                   node.AncestorsAndSelf().OfType<FieldDeclarationSyntax>().FirstOrDefault() != null;
        }

        public override SyntaxNode GetVariableDeclaratorOfAFieldDeclarationNode(SyntaxNode node)
        {
            if (!IsObjectCreationExpressionUnderFieldDeclaration(node))
            {
                return null;
            }

            return node.AncestorsAndSelf().OfType<VariableDeclaratorSyntax>().FirstOrDefault();
        }

        public override bool IsObjectConstructionForTemporaryObject(SyntaxNode node)
        {
            if (node == null)
            {
                return false;
            }

            SyntaxKind kind = node.Kind();
            if (kind != SyntaxKind.ObjectCreationExpression)
            {
                return false;
            }

            return node.Parent?.Kind() != SyntaxKind.EqualsValueClause;
        }

        public override bool IsAttributeArgument(SyntaxNode node)
        {
            return node?.Kind() == SyntaxKind.AttributeArgument;
        }

        public override SyntaxNode GetAttributeArgumentNode(SyntaxNode node)
        {
            return ((AttributeArgumentSyntax)node)?.NameEquals?.Name;
        }
    }
}
