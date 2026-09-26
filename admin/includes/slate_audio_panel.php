<?php $slateAudio = $db->query("SELECT key, value FROM settings WHERE key IN ('slate_audio_file','slate_audio_url','slate_audio_volume')")->fetchAll(PDO::FETCH_KEY_PAIR); ?>
<div class="sv-panel">
  <h2>Slate audio</h2>
  <p class="sv-help">Current source: <?= isset($slateAudio['slate_audio_file']) ? 'uploaded file' : (isset($slateAudio['slate_audio_url']) ? 'radio URL' : 'silence') ?>. Running slates refresh within about 30 seconds. Public broadcasts require music rights.</p>
  <form action="settings.php" method="post" enctype="multipart/form-data">
    <?= sv_csrf_field() ?><input type="hidden" name="action" value="save_slate_audio">
    <label for="slate-file">Upload audio (MP3, OGG, OPUS, FLAC, AAC, M4A, WAV; max 25 MB)</label>
    <input id="slate-file" type="file" name="slate_audio_file" accept=".mp3,.ogg,.opus,.flac,.aac,.m4a,.wav,audio/*">
    <label for="slate-url">Or radio stream URL</label>
    <input id="slate-url" type="url" name="slate_audio_url" maxlength="2048" value="<?= h($slateAudio['slate_audio_url'] ?? '') ?>" placeholder="https://example.org/radio.mp3">
    <label for="slate-volume">Volume (0–100)</label>
    <input id="slate-volume" type="number" name="slate_audio_volume" min="0" max="100" value="<?= h($slateAudio['slate_audio_volume'] ?? '50') ?>" required>
    <button type="submit" class="btn-primary" style="margin-top:1rem">Save audio</button>
  </form>
  <form action="settings.php" method="post" data-confirm="Disable slate audio?" style="margin-top:1rem">
    <?= sv_csrf_field() ?><input type="hidden" name="action" value="disable_slate_audio">
    <button type="submit" class="btn-danger">Disable and remove audio</button>
  </form>
</div>
