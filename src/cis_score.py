from utils.logger import info, warning, error

# CIS categories and their weights (example values)
CATEGORIES = {
    'Network': 0.25,
    'User': 0.25,
    'Service': 0.25,
    'FileSystem': 0.25,
}

# Each check is a tuple: (category, description, passed)
class CISScorer:
    def __init__(self):
        self.checks = []

    def add_check(self, category, description, passed):
        self.checks.append((category, description, passed))
        if passed:
            info(f'CIS PASS: [{category}] {description}')
        else:
            warning(f'CIS FAIL: [{category}] {description}')

    def score(self):
        summary = {cat: {'total': 0, 'passed': 0} for cat in CATEGORIES}
        for cat, desc, passed in self.checks:
            summary[cat]['total'] += 1
            if passed:
                summary[cat]['passed'] += 1
        breakdown = {}
        total_score = 0.0
        for cat, weight in CATEGORIES.items():
            if summary[cat]['total'] == 0:
                cat_score = 1.0  # If no checks, count as perfect
            else:
                cat_score = summary[cat]['passed'] / summary[cat]['total']
            breakdown[cat] = round(cat_score * 100, 1)
            total_score += cat_score * weight
        final_score = round(total_score * 100, 1)
        info(f'CIS Benchmark Score: {final_score} (breakdown: {breakdown})')
        return final_score, breakdown

if __name__ == "__main__":
    scorer = CISScorer()
    # Example usage
    scorer.add_check('Network', 'Firewall enabled', False)
    scorer.add_check('Service', 'No legacy services', True)
    scorer.add_check('FileSystem', '/etc/shadow permissions', False)
    scorer.add_check('User', 'SSH root login disabled', True)
    final, breakdown = scorer.score()
    print(f"Final CIS Score: {final}")
    print(f"Breakdown: {breakdown}") 