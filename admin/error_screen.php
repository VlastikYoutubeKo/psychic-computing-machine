<?php
declare(strict_types=1);
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/csrf.php';
require_once __DIR__ . '/includes/secret_box.php';
require_once __DIR__ . '/includes/slate_copy.php';
$operator = sv_require_login();
$db = sv_db();
$suggestion = null;
$suggestionReason = '';
$localError = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    sv_csrf_check();
    $reason = (string) ($_POST['reason'] ?? '');
    $action = (string) ($_POST['action'] ?? '');
    if (!isset(SV_SLATE_REASONS[$reason])) {
        $localError = 'Select a valid reason.';
    } elseif ($action === 'save_slate_text') {
        $copy = sv_slate_copy_valid((string) ($_POST['title'] ?? ''), (string) ($_POST['subtitle'] ?? ''));
        if ($copy === null) {
            $localError = 'Title must be 1–32 characters; subtitle 1–90 characters in at most two lines. No control characters, URLs or emojis.';
            $suggestion = ['title' => (string) ($_POST['title'] ?? ''), 'subtitle' => (string) ($_POST['subtitle'] ?? '')];
            $suggestionReason = $reason;
        } else {
            $db->prepare("UPDATE slate_texts SET title = ?, subtitle = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE reason = ?")
                ->execute([$copy['title'], $copy['subtitle'], $reason]);
            sv_audit('slate_text_updated', 'reason:' . $reason);
            sv_flash('ok', 'Error text saved. Running slates refresh within about 30 seconds.');
            sv_redirect('error_screen.php#' . $reason);
        }
    } elseif ($action === 'generate_slate_text') {
        $result = sv_ai_generate($db, (int) $operator['id'], $reason, (string) ($_POST['language'] ?? 'en'), (string) ($_POST['instruction'] ?? ''));
        if (isset($result['copy'])) {
            $suggestion = $result['copy'];
            $suggestionReason = $reason;
            sv_audit('slate_text_ai_suggested', 'reason:' . $reason);
        } else {
            $localError = $result['error'] ?? 'Could not generate a suggestion.';
        }
    } else {
        $localError = 'Unknown action.';
    }
}

$rows = $db->query('SELECT reason, title, subtitle FROM slate_texts')->fetchAll(PDO::FETCH_UNIQUE);
$pageTitle = 'Error screen';
$activeNav = 'error_screen';
require __DIR__ . '/includes/layout_top.php';
?>
<div class="sv-page-heading"><div><h1>Error screen</h1><p class="sv-help">Edit the wording viewers see in both the video and browser page. Changes reach running slates within about 30 seconds.</p></div></div>
<?php if ($localError !== ''): ?><div class="sv-flash err"><?= h($localError) ?></div><?php endif; ?>
<div class="sv-panel"><h2>Preview</h2><p class="sv-help">These are the rendered backgrounds; live title, subtitle, clock and cut-off time are added by the gateway.</p>
  <div class="sv-preview-grid">
    <figure><img src="assets/slate-unavailable.png" alt="Unavailable slate background"><figcaption>Unavailable</figcaption></figure>
    <figure><img src="assets/slate-temporary.png" alt="Temporary slate background"><figcaption>Temporarily unavailable</figcaption></figure>
  </div>
</div>
<div class="sv-panel"><h2>Text by reason</h2><p class="sv-help">Title: at most 32 characters. Subtitle: at most 90 characters, up to two lines. AI only fills a suggestion; Save is always separate.</p></div>
<?php foreach (SV_SLATE_REASONS as $reason => $label):
    $saved = $rows[$reason] ?? ['title' => '', 'subtitle' => ''];
    $current = $suggestionReason === $reason && $suggestion !== null ? $suggestion : $saved;
?>
<section class="sv-panel" id="<?= h($reason) ?>">
  <h2><?= h($label) ?></h2>
  <form method="post">
    <?= sv_csrf_field() ?><input type="hidden" name="action" value="save_slate_text"><input type="hidden" name="reason" value="<?= h($reason) ?>">
    <label for="title-<?= h($reason) ?>">Title</label><input id="title-<?= h($reason) ?>" name="title" maxlength="32" value="<?= h($current['title']) ?>" required>
    <label for="subtitle-<?= h($reason) ?>">Subtitle</label><textarea id="subtitle-<?= h($reason) ?>" name="subtitle" maxlength="90" rows="2" required><?= h($current['subtitle']) ?></textarea>
    <button class="btn-primary" type="submit">Save text</button>
  </form>
  <form method="post" class="sv-ai-form">
    <?= sv_csrf_field() ?><input type="hidden" name="action" value="generate_slate_text"><input type="hidden" name="reason" value="<?= h($reason) ?>">
    <label for="language-<?= h($reason) ?>">AI language</label><select id="language-<?= h($reason) ?>" name="language"><option value="en">English</option><option value="cs">Čeština</option></select>
    <label for="instruction-<?= h($reason) ?>">Optional tone or language instruction</label><input id="instruction-<?= h($reason) ?>" name="instruction" maxlength="200" placeholder="Keep it warm and concise">
    <button class="btn" type="submit">Generate with AI</button>
  </form>
  <?php if ($suggestionReason === $reason && $suggestion !== null): ?><p class="sv-flash ok">AI suggestion filled above. Review it, then click Save text.</p><?php endif; ?>
</section>
<?php endforeach; ?>
<?php require __DIR__ . '/includes/slate_audio_panel.php'; ?>
<?php require __DIR__ . '/includes/layout_bottom.php'; ?>
