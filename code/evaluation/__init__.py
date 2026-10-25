"""Independent prediction evaluation framework.

This package may import the prediction-facing ``ghost_audit`` contracts, but
``ghost_audit`` must never import this package or its reference answers.
"""

from evaluation.evaluator import EvaluationInputError, evaluate_files

__all__ = ["EvaluationInputError", "evaluate_files"]
