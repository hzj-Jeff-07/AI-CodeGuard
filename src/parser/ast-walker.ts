import type { ASTNode } from '../types/index.js';

export interface ASTVisitor {
  enter?(node: ASTNode, parent: ASTNode | null): boolean | void;
  leave?(node: ASTNode, parent: ASTNode | null): void;
}

export function walkAST(root: ASTNode, visitor: ASTVisitor): void {
  visitNode(root, null, visitor);
}

function visitNode(node: ASTNode, parent: ASTNode | null, visitor: ASTVisitor): void {
  const shouldContinue = visitor.enter?.(node, parent);
  if (shouldContinue === false) return;

  for (const child of node.children) {
    visitNode(child, node, visitor);
  }

  visitor.leave?.(node, parent);
}
