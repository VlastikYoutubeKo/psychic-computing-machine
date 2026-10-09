-- Revoked access points can't be un-revoked, so they no longer count toward a
-- user's access point limit: only active ones do.
DROP TRIGGER IF EXISTS limit_user_access_points;
CREATE TRIGGER limit_user_access_points BEFORE INSERT ON access_points
WHEN (SELECT role FROM operators WHERE id=(SELECT owner_id FROM streams WHERE id=NEW.stream_id))='user'
AND (SELECT COUNT(*) FROM access_points WHERE status='active' AND stream_id IN
  (SELECT id FROM streams WHERE owner_id=(SELECT owner_id FROM streams WHERE id=NEW.stream_id))) >=
  (SELECT max_access_points FROM operators WHERE id=(SELECT owner_id FROM streams WHERE id=NEW.stream_id))
BEGIN SELECT RAISE(ABORT,'access point quota reached'); END;
