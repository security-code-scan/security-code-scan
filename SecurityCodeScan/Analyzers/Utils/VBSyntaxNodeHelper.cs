#nullable disable
using System.Collections.Generic;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.VisualBasic;
using Microsoft.CodeAnalysis.VisualBasic.Syntax;

namespace SecurityCodeScan.Analyzers.Utils
{
    internal sealed class VBSyntaxNodeHelper : SyntaxNodeHelper
    {
        public static VBSyntaxNodeHelper Default { get; } = new VBSyntaxNodeHelper();

        private VBSyntaxNodeHelper()
        {
        }

        public override ITypeSymbol GetClassDeclarationTypeSymbol(SyntaxNode node, SemanticModel semanticModel)
        {
            if (node == null)
            {
                return null;
            }

            SyntaxKind kind = node.Kind();
            if (kind == SyntaxKind.ClassBlock)
            {
                return semanticModel.GetDeclaredSymbol((ClassBlockSyntax)node);
            }

            return null;
        }

        public override SyntaxNode GetAssignmentLeftNode(SyntaxNode node)
        {
            if (node == null)
            {
                return null;
            }

            SyntaxKind kind = node.Kind();
            switch (kind)
            {
                case SyntaxKind.AddAssignmentStatement:
                case SyntaxKind.SimpleAssignmentStatement:
                    return ((AssignmentStatementSyntax)node).Left;
                case SyntaxKind.VariableDeclarator:
                    return ((VariableDeclaratorSyntax)node).Names.First();
                case SyntaxKind.NamedFieldInitializer:
                    return ((NamedFieldInitializerSyntax)node).Name;
            }

            return null;
        }

        public override string GetAssignmentLeftNodeName(SyntaxNode node)
        {
            if (node == null)
            {
                return null;
            }

            SyntaxKind kind = node.Kind();
            switch (kind)
            {
                case SyntaxKind.AddAssignmentStatement:
                case SyntaxKind.SimpleAssignmentStatement:
                    return ((AssignmentStatementSyntax)node).Left.ToString();
                case SyntaxKind.VariableDeclarator:
                    return ((VariableDeclaratorSyntax)node).Names.First().ToString();
                case SyntaxKind.NamedFieldInitializer:
                    return ((NamedFieldInitializerSyntax)node).Name.ToString();
            }

            return null;
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
                case SyntaxKind.SimpleAssignmentStatement:
                    return ((AssignmentStatementSyntax)node).Right;
                case SyntaxKind.VariableDeclarator:
                    var decl = (VariableDeclaratorSyntax)node;
                    if (decl.Initializer != null)
                    {
                        return decl.Initializer.Value;
                    }

                    if (decl.AsClause != null)
                    {
                        if (decl.AsClause is AsNewClauseSyntax asNewClause)
                            return asNewClause.NewExpression;

                        return decl.AsClause;
                    }

                    break;
                case SyntaxKind.NamedFieldInitializer:
                    return ((NamedFieldInitializerSyntax)node).Expression;
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
                var memberAccessExpr = ((MemberAccessExpressionSyntax)node).Expression;
                if (memberAccessExpr != null)
                    return memberAccessExpr;

                if (node?.Parent?.Parent.Kind() == SyntaxKind.ConditionalAccessExpression)
                {
                    return ((ConditionalAccessExpressionSyntax)node.Parent.Parent).Expression;
                }
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
            if (kind == SyntaxKind.InvocationExpression)
            {
                return ((InvocationExpressionSyntax)node).Expression;
            }

            return null;
        }

        public override SyntaxNode GetAttributeArgumentExpressionNode(SyntaxNode node)
        {
            if (!(node is ArgumentSyntax argument))
                return null;

            return argument.GetExpression();
        }

        public override SyntaxNode GetDefaultValueForAnOptionalParameter(SyntaxNode declNode, int paramIndex)
        {
            if (declNode == null)
            {
                return null;
            }

            var methodDecl = (MethodBlockBaseSyntax)declNode;

            ParameterListSyntax paramList = methodDecl.BlockStatement.ParameterList;
            if (paramIndex >= paramList.Parameters.Count)
                return null;

            EqualsValueSyntax equalsValueNode = paramList.Parameters[paramIndex].Default;
            if (equalsValueNode != null)
            {
                return equalsValueNode.Value;
            }

            return null;
        }

        protected override IEnumerable<SyntaxNode> GetCallArgumentExpressionNodes(SyntaxNode node, CallKind callKind)
        {
            if (node == null)
            {
                return null;
            }

            ArgumentListSyntax argList = null;
            SyntaxKind         kind    = node.Kind();
            switch (kind)
            {
                case SyntaxKind.InvocationExpression when (callKind & CallKind.Invocation) != 0:
                    argList = ((InvocationExpressionSyntax)node).ArgumentList;
                    break;
                case SyntaxKind.ObjectCreationExpression when (callKind & CallKind.ObjectCreation) != 0:
                    argList = ((ObjectCreationExpressionSyntax)node).ArgumentList;
                    break;
            }

            if (argList != null)
            {
                return from arg in argList.Arguments select arg.GetExpression();
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

            ObjectCreationExpressionSyntax objectCreationNode =
                node.DescendantNodesAndSelf().OfType<ObjectCreationExpressionSyntax>().FirstOrDefault();

            if (objectCreationNode == null)
            {
                return empty;
            }

            if (objectCreationNode.Initializer == null)
            {
                return empty;
            }

            SyntaxKind kind = objectCreationNode.Initializer.Kind();
            if (kind != SyntaxKind.ObjectMemberInitializer)
            {
                return empty;
            }

            var initializer = (ObjectMemberInitializerSyntax)objectCreationNode.Initializer;
            return initializer.Initializers
                              .Where(fieldInitializer => fieldInitializer.Kind() == SyntaxKind.NamedFieldInitializer)
                              .Select(fieldInitializer => (NamedFieldInitializerSyntax)fieldInitializer);
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
            if (node == null)
            {
                return null;
            }

            SyntaxKind kind   = node.Kind();
            ISymbol    symbol = GetReferencedSymbol(node, semanticModel);
            if (symbol == null
                && kind == SyntaxKind.AsNewClause)
            {
                symbol = GetReferencedSymbol(node.ChildNodes().First(), semanticModel);
            }

            if (symbol == null)
                return null;

            if (symbol.Kind == SymbolKind.Method)
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

            MethodBlockSyntax declaration = node.AncestorsAndSelf().OfType<MethodBlockSyntax>().FirstOrDefault();
            if (declaration != null)
            {
                return semanticModel.GetDeclaredSymbol(declaration);
            }

            SubNewStatementSyntax constructor = node.AncestorsAndSelf().OfType<SubNewStatementSyntax>().FirstOrDefault();
            if (constructor != null)
            {
                return semanticModel.GetDeclaredSymbol(constructor);
            }

            return null;
        }

        public override ITypeSymbol GetEnclosingTypeSymbol(SyntaxNode node, SemanticModel semanticModel)
        {
            if (node == null)
            {
                return null;
            }

            ClassBlockSyntax declaration = node.AncestorsAndSelf().OfType<ClassBlockSyntax>().FirstOrDefault();
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

            return node.DescendantNodesAndSelf().OfType<AssignmentStatementSyntax>();
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
                case SyntaxKind.PropertyBlock:
                    attributeLists = ((PropertyBlockSyntax)node).PropertyStatement.AttributeLists;
                    break;
                case SyntaxKind.FunctionBlock:
                case SyntaxKind.SubBlock:
                    attributeLists = ((MethodBlockSyntax)node).BlockStatement.AttributeLists;
                    break;
                case SyntaxKind.ClassBlock:
                    attributeLists = ((ClassBlockSyntax)node).ClassStatement.AttributeLists;
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
            return node                                                                      != null                                &&
                   node.Kind()                                                               == SyntaxKind.ObjectCreationExpression &&
                   node.AncestorsAndSelf().OfType<FieldDeclarationSyntax>().FirstOrDefault() != null;
        }

        public override SyntaxNode GetVariableDeclaratorOfAFieldDeclarationNode(SyntaxNode objectCreationExpression)
        {
            if (!IsObjectCreationExpressionUnderFieldDeclaration(objectCreationExpression))
            {
                return null;
            }

            return objectCreationExpression.AncestorsAndSelf().OfType<VariableDeclaratorSyntax>().FirstOrDefault();
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

            var parentKind = node.Parent?.Kind();
            return parentKind != SyntaxKind.AsNewClause && parentKind != SyntaxKind.EqualsValue;
        }

        public override bool IsAttributeArgument(SyntaxNode node)
        {
            return node?.Kind() == SyntaxKind.SimpleArgument;
        }

        public override SyntaxNode GetAttributeArgumentNode(SyntaxNode node)
        {
            return ((SimpleArgumentSyntax)node)?.NameColonEquals?.Name;
        }
    }
}
