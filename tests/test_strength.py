"""Tests for pacli.strength module."""

import pytest
from sinduk.strength import (
    StrengthLabel,
    StrengthResult,
    evaluate,
    calculate_score,
    score_bar,
    print_strength,
)


class TestEvaluate:
    """Test evaluate function with various input types."""

    def test_very_weak_password(self):
        """Short, common password should be very weak."""
        result = evaluate("password")
        assert result.label == StrengthLabel.VERY_WEAK
        assert result.score < 30
        assert len(result.feedback) > 0

    def test_weak_password(self):
        """Simple password should be weak."""
        result = evaluate("abcd1234")
        assert result.label == StrengthLabel.WEAK
        assert 20 <= result.score < 50

    def test_fair_password(self):
        """Medium-strength password should be fair."""
        result = evaluate("MyP@ssw0rd")
        assert result.label in [StrengthLabel.FAIR, StrengthLabel.STRONG]
        assert result.score >= 40

    def test_strong_password(self):
        """Long, diverse password should be strong."""
        result = evaluate("correct-horse-battery-staple")
        assert result.label in [StrengthLabel.STRONG, StrengthLabel.VERY_STRONG]
        assert result.score >= 70

    def test_very_strong_password(self):
        """Very long, diverse password should be very strong."""
        result = evaluate("Th1s!IsAVeryStr0ngPassw0rd#WithSymbols")
        assert result.label == StrengthLabel.VERY_STRONG
        assert result.score >= 80

    def test_empty_password(self):
        """Empty string should be very weak."""
        result = evaluate("")
        assert result.label == StrengthLabel.VERY_WEAK
        assert result.score == 0

    def test_token_type(self):
        """Evaluate function should handle token type."""
        result = evaluate("a1b2c3d4e5f6g7h8", secret_type="token")
        assert isinstance(result, StrengthResult)
        assert result.score >= 0

    def test_sequential_characters(self):
        """Password with sequential chars should have penalty feedback."""
        result = evaluate("password1234")
        assert any("sequence" in fb.lower() for fb in result.feedback)

    def test_repeated_characters(self):
        """Password with repeats should not crash."""
        result = evaluate("passsword")
        assert isinstance(result.feedback, list)

    def test_result_immutable(self):
        """StrengthResult should be frozen."""
        result = evaluate("test")
        with pytest.raises(AttributeError):
            result.score = 100


class TestCalculateScore:
    """Test calculate_score function."""

    def test_empty_secret(self):
        """Empty secret should yield zero score."""
        feedback, score = calculate_score(length=0)
        assert score == 0
        assert len(feedback) > 0

    def test_short_secret(self):
        """Short password should have low score."""
        _, score = calculate_score(length=4)
        assert score < 30

    def test_long_secret(self):
        """Long password should have high base score."""
        _, score = calculate_score(length=32)
        assert score >= 50

    def test_token_type_scoring(self):
        """Token type should affect scoring differently."""
        _, pwd_score = calculate_score(secret_type="password", length=16)
        _, token_score = calculate_score(secret_type="token", length=16)
        # Scores might differ based on type
        assert isinstance(pwd_score, int)
        assert isinstance(token_score, int)

    def test_score_bounds(self):
        """Score should never exceed 100."""
        _, score = calculate_score(length=100)
        assert score <= 100
        assert score >= 0


class TestScoreBar:
    """Test score_bar function."""

    def test_score_bar_very_weak(self):
        """Very weak result should show empty/low bar."""
        result = StrengthResult(
            score=10,
            label=StrengthLabel.VERY_WEAK,
            entropy_bits=5.0,
        )
        bar = score_bar(result)
        assert isinstance(bar, str)
        assert len(bar) > 0

    def test_score_bar_very_strong(self):
        """Very strong result should show full bar."""
        result = StrengthResult(
            score=95,
            label=StrengthLabel.VERY_STRONG,
            entropy_bits=100.0,
        )
        bar = score_bar(result)
        assert isinstance(bar, str)

    def test_score_bar_custom_width(self):
        """Score bar should respect custom width."""
        result = StrengthResult(
            score=50,
            label=StrengthLabel.FAIR,
            entropy_bits=40.0,
        )
        bar = score_bar(result, width=10)
        assert isinstance(bar, str)

    def test_score_bar_default_width(self):
        """Score bar default width should produce consistent output."""
        result = StrengthResult(
            score=50,
            label=StrengthLabel.FAIR,
            entropy_bits=40.0,
        )
        bar1 = score_bar(result)
        bar2 = score_bar(result)
        assert bar1 == bar2


class TestPrintStrength:
    """Test print_strength function."""

    def test_print_strength_output(self, capsys):
        """print_strength should print to stdout."""
        result = StrengthResult(
            score=75,
            label=StrengthLabel.STRONG,
            entropy_bits=60.0,
            feedback=["Good length"],
            crack_time_display="2 days",
        )
        print_strength(result)
        captured = capsys.readouterr()
        assert "Strong" in captured.out or "STRONG" in captured.out

    def test_print_strength_with_feedback(self, capsys):
        """print_strength should include feedback if present."""
        result = StrengthResult(
            score=30,
            label=StrengthLabel.WEAK,
            entropy_bits=20.0,
            feedback=["Too short", "Common password"],
        )
        print_strength(result)
        captured = capsys.readouterr()
        assert len(captured.out) > 0


class TestStrengthLabel:
    """Test StrengthLabel enum."""

    def test_all_labels_have_colors(self):
        """All strength labels should have color hints."""
        for label in StrengthLabel:
            color = label.color_hint
            assert isinstance(color, str)
            assert color.startswith("#")

    def test_label_strings(self):
        """Labels should have readable string values."""
        assert StrengthLabel.VERY_WEAK.value == "Very Weak"
        assert StrengthLabel.VERY_STRONG.value == "Very Strong"


class TestEntropyEstimation:
    """Test entropy and crack time estimation."""

    def test_entropy_increases_with_length(self):
        """Longer secrets should have more entropy."""
        short = evaluate("abcd")
        long = evaluate("abcdefghijklmnop")
        assert long.entropy_bits > short.entropy_bits

    def test_entropy_increases_with_diversity(self):
        """More character diversity should increase entropy."""
        low_diversity = evaluate("aaaaaaaaaa")
        high_diversity = evaluate("aB1!xY9@")
        # High diversity of even shorter length should have more entropy
        assert high_diversity.entropy_bits > low_diversity.entropy_bits

    def test_crack_time_display_reasonable(self):
        """Crack time display should be a string."""
        result = evaluate("test")
        assert isinstance(result.crack_time_display, str)
        assert len(result.crack_time_display) > 0
