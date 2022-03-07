export const paginationHelper = (
  page?: string,
  pageSize?: string,
): { take: number; skip: number } => {
  let take = 0,
    skip = 0;
  if (pageSize && parseInt(pageSize)) {
    take = parseInt(pageSize);
  }

  if (take && page && parseInt(page)) {
    skip = (parseInt(page) - 1) * take;
  }

  return {
    take,
    skip,
  };
};
