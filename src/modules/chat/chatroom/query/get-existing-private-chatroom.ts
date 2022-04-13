export const GET_EXISTING_PRIVATE_CHATROOM = `
  SELECT
  c.id AS id,
  c.name AS name,
  cp.participants AS participants
  FROM
  chatroom c
  INNER JOIN (
    SELECT
      cpu. "chatroomId" AS chatroomId,
      array_agg(DISTINCT cpu. "userId") AS participants
    FROM
      chatroom_participants_user cpu
    GROUP BY
      cpu. "chatroomId") AS cp ON cp.chatroomId = c.id
  AND array_length(cp.participants, 1) = 2
  AND cp.participants <@ $1::uuid [];
  LIMIT $2
  OFFSET $3
`;
