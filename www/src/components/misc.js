import React, { Component } from 'react';
import PropTypes from 'prop-types';
import M from 'materialize-css';

export const Loader = () => (
    <div className="center">
        <br /><br />
        <div className="preloader-wrapper big active">
            <div className="spinner-layer spinner-blue-only">
                <div className="circle-clipper left">
                    <div className="circle"></div>
                </div>
                <div className="gap-patch">
                    <div className="circle"></div>
                </div>
                <div className="circle-clipper right">
                    <div className="circle"></div>
                </div>
            </div>
        </div>
    </div>
)


export class SearchTabs extends Component {

    // TODO: this not so good
    constructor(props) {
        super(props);
        this.ref = React.createRef();
    }

    componentDidMount() {
        this.self = M.Tabs.init(this.ref.current)
    }

    componentWillUnmount() {
        this.self.destroy();
        this.self = null;
    }

    handleClick() {
        this.props.handleClick(this.self.index)
    }

    render() {
        return (
            <ul className="tabs tabs-fixed-width" ref={this.ref} >
                <li className="tab"><a className="active" style={{ cursor: 'pointer' }} onClick={() => this.handleClick()}>Virksomhet</a></li>
                <li className="tab"><a style={{ cursor: 'pointer' }} onClick={() => this.handleClick()}>Person</a></li>
            </ul>
        )
    }
}

SearchTabs.propTypes = {
    handleClick: PropTypes.func,
}
