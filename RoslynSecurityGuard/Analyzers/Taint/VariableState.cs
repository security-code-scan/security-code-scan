using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Collections.Generic;
using static RoslynSecurityGuard.Analyzers.Taint.VariableTaint;

namespace RoslynSecurityGuard.Analyzers.Taint
{
	/// <summary>
	/// Define the state of variable regarding can it be trust, where does it come from.
	/// 
	/// <code>struct</code> was chosen because the execution of the taint analysis will visited a lot.
	/// This may allow less heap allocation and less garbage collection.
	/// 
	/// <a href="https://msdn.microsoft.com/en-us/library/ms229017.aspx">Choosing Between Class and Struct</a>
	/// </summary>
	public struct VariableState
	{
		public VariableTaint taint { get; }

		public List<VariableTag> tags { get; private set; }

		public SyntaxNode node { get; private set; }

		/// <summary>
		/// Constructor
		/// </summary>
		/// <param name="taint">Initial state</param>
		public VariableState(SyntaxNode p_node, VariableTaint taint = UNKNOWN, List<VariableTag> p_tags = null)
		{
			this.taint = taint;
			if (p_tags == null)
			{
				this.tags = new List<VariableTag>();
			}
			else
			{
				tags = p_tags;
			}
			node = p_node;
		}

		/// <summary>
		/// Merge two different states. State are merge if a data structure accept new input or 
		/// if values are concatenate.
		/// </summary>
		/// <param name="secondState"></param>
		/// <returns></returns>
		public VariableState merge(VariableState secondState)
		{
			var newTaint = taint;

			switch (secondState.taint)
			{
				case (TAINTED):
					newTaint = TAINTED;
					break;
				case (UNKNOWN):
					if (taint != TAINTED) newTaint = UNKNOWN;
					break;
				case (SAFE):
					if (taint != TAINTED && taint != UNKNOWN) newTaint = SAFE;
					break;
				case (CONSTANT):
					if (taint == SAFE) newTaint = SAFE;
					else if (taint == CONSTANT) newTaint = CONSTANT;
					break;
			}

			// A new instance is made to prevent referencing the current VariableState's parameters
			var vs = new VariableState(node, newTaint);

			// Searches through the current VariableState for unique tags
			foreach (var newTag in tags)
			{
				vs.AddTag(newTag);
			}

			// Searches through the new VariableState for new tags
			foreach (var newTag in secondState.tags)
			{
				vs.AddTag(newTag);
			}

			return vs;

		}

		public override string ToString()
		{
			return taint.ToString();
		}

		/// <summary>
		/// Will only add a new tag to the list if it is not already present in the list
		/// </summary>
		/// <param name="tag"></param>
		/// <returns>A VariabeState with the updated list</returns>
		public VariableState AddTag(VariableTag tag)
		{
			if (!tags.Contains(tag))
			{
				tags.Add(tag);				
			}
			return this;
		}

		public VariableState AddSyntaxNode(SyntaxNode node)
		{
			this.node = node;
			return this;
		}
	}
}
