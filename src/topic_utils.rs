#[derive(Debug, PartialEq, Clone, Eq)]
pub enum TopicPathElement {
    Topic(String),
    WildcardSingleLevel,
    WildcardMultiLevel,
}

#[derive(Debug)]
pub enum TopicPathError {
    InvalidTopicName(String),
    TopicAfterMultiLevelWildcard,
    WildcardInTopic,
}

#[derive(Debug, PartialEq, Clone, Eq)]
pub struct TopicPath(pub Vec<TopicPathElement>);

pub fn parse_topic_path(
    path_str: &str,
    may_contain_wildcard: bool,
) -> Result<TopicPath, TopicPathError> {
    let mut path = TopicPath(Vec::new());
    let mut last = 0;
    let len = path_str.len();
    for (mut index, _) in path_str.match_indices('/') {
        index += 1;
        if index < len {
            let substring = &path_str[last..index];
            last = index;
            let element = parse_topic_path_element(substring, may_contain_wildcard)?;

            if element == TopicPathElement::WildcardMultiLevel {
                return Err(TopicPathError::TopicAfterMultiLevelWildcard);
            }
            path.0.push(element);
        }
    }
    if last < len {
        path.0.push(parse_topic_path_element(
            &path_str[last..],
            may_contain_wildcard,
        )?)
    }
    Ok(path)
}

fn parse_topic_path_element(
    substring: &str,
    may_contain_wildcard: bool,
) -> Result<TopicPathElement, TopicPathError> {
    match (substring.chars().nth(0).unwrap(), may_contain_wildcard) {
        ('#', true) => Ok(TopicPathElement::WildcardMultiLevel),
        ('+', true) => Ok(TopicPathElement::WildcardSingleLevel),
        ('#', false) | ('+', false) => Err(TopicPathError::WildcardInTopic),
        (_, _) => {
            if substring.contains(|c| c == '+' || c == '#') {
                Err(TopicPathError::InvalidTopicName(substring.to_string()))
            } else {
                Ok(TopicPathElement::Topic(substring.to_string()))
            }
        }
    }
}

pub fn match_topic_to_topic_filter(filter: &TopicPath, topic: &TopicPath) -> bool {
    let filter_iter = filter.0.iter();
    let mut topic_iter = topic.0.iter().clone();
    for filter_element in filter_iter {
        let topic_element = topic_iter.next();
        match topic_element {
            None => return false,
            Some(topic_element) => match filter_element {
                &TopicPathElement::WildcardMultiLevel => return true,
                &TopicPathElement::WildcardSingleLevel => {
                    if topic_element == &TopicPathElement::WildcardMultiLevel {
                        return false;
                    }
                }
                element @ &TopicPathElement::Topic(_) => {
                    if element != topic_element {
                        return false;
                    }
                }
            },
        }
    }
    topic_iter.next().is_none()
}

#[cfg(test)]
mod tests {
    use super::TopicPathElement::*;
    use super::*;

    #[test]
    fn test_parse_topic_path() {
        assert_eq!(
            TopicPath(vec![
                Topic("/".to_string()),
                WildcardSingleLevel,
                Topic("abc/".to_string()),
                Topic("123/".to_string()),
                WildcardMultiLevel
            ]),
            parse_topic_path("/+/abc/123/#", true).unwrap()
        );

        assert_eq!(
            TopicPath(vec![WildcardMultiLevel]),
            parse_topic_path("#", true).unwrap()
        );

        assert_eq!(
            TopicPath(vec![Topic("/".to_string()), Topic("123".to_string())]),
            parse_topic_path("/123", false).unwrap()
        );
    }

    #[should_panic]
    #[test]
    fn test_parse_topic_path_invalid_wildcard_multilevel() {
        parse_topic_path("#/abc", false).unwrap();
    }

    #[should_panic]
    #[test]
    fn test_parse_topic_path_invalid_topic_plus() {
        parse_topic_path("abc/ab+cd", false).unwrap();
    }

    #[should_panic]
    #[test]
    fn test_parse_topic_path_invalid_topic_hash() {
        parse_topic_path("abc/ab#cd", false).unwrap();
    }

    #[test]
    fn test_match_topic_topic() {
        assert_eq!(
            match_topic_to_topic_filter(
                &TopicPath(vec![Topic("/".to_string()),]),
                &TopicPath(vec![Topic("/".to_string()), Topic("xyz/".to_string()),])
            ),
            false
        );

        assert_eq!(
            match_topic_to_topic_filter(
                &TopicPath(vec![
                    Topic("/".to_string()),
                    WildcardSingleLevel,
                    Topic("abc/".to_string()),
                    Topic("123/".to_string()),
                    WildcardMultiLevel
                ]),
                &TopicPath(vec![
                    Topic("/".to_string()),
                    Topic("xyz".to_string()),
                    Topic("abc/".to_string()),
                    Topic("123/".to_string()),
                    Topic("890".to_string())
                ])
            ),
            true
        );

        assert_eq!(
            match_topic_to_topic_filter(
                &TopicPath(vec![
                    Topic("/".to_string()),
                    WildcardSingleLevel,
                    Topic("abc/".to_string()),
                    Topic("123/".to_string()),
                    WildcardMultiLevel
                ]),
                &TopicPath(vec![
                    Topic("/".to_string()),
                    Topic("xyz".to_string()),
                    Topic("abd/".to_string()),
                    Topic("123/".to_string()),
                    Topic("890".to_string())
                ])
            ),
            false
        );

        assert_eq!(
            match_topic_to_topic_filter(
                &TopicPath(vec![
                    Topic("/".to_string()),
                    WildcardSingleLevel,
                    Topic("abc/".to_string()),
                    Topic("123/".to_string())
                ]),
                &TopicPath(vec![
                    Topic("/".to_string()),
                    Topic("xyz/".to_string()),
                    Topic("abc/".to_string()),
                    Topic("123/".to_string()),
                    Topic("890".to_string())
                ])
            ),
            false
        );

        assert_eq!(
            match_topic_to_topic_filter(
                &TopicPath(vec![
                    Topic("/".to_string()),
                    WildcardSingleLevel,
                    Topic("abc/".to_string()),
                    Topic("123/".to_string()),
                    WildcardMultiLevel
                ]),
                &TopicPath(vec![
                    Topic("/".to_string()),
                    Topic("abc/".to_string()),
                    Topic("123/".to_string()),
                    Topic("890".to_string()),
                    Topic("890".to_string())
                ])
            ),
            false
        );
    }
}
